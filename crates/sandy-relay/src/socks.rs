//! The server side of the SOCKS5 handshake (RFC 1928) that the egress broker speaks, and no more
//! of the protocol: no authentication (method 0 only), one CONNECT request to an IPv4 or IPv6
//! address, and the replies.
//!
//! Every read has a length that the protocol fixes or that one byte gives, into a buffer of fixed
//! size, and the whole handshake has `HANDSHAKE_TIMEOUT`; nothing the client sends decides how
//! much memory or time it takes. Exactly the bytes of the handshake are read, so data that the
//! client sends behind its request stays in the socket for the relay. The few bytes written
//! before the relay starts fit into an empty send buffer, so writes need no timeout.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// How long a client may take from its connection to the end of its request. A client that sends
/// nothing, or sends slowly, cannot hold one of the broker's connections for longer.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const VERSION: u8 = 5;
const NO_AUTHENTICATION: u8 = 0;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT: u8 = 1;
const IPV4: u8 = 1;
const DOMAIN_NAME: u8 = 3;
const IPV6: u8 = 4;

/// The replies of RFC 1928, section 6, that the broker sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Succeeded = 0,
    GeneralFailure = 1,
    /// "Connection not allowed by ruleset": the destination check refused it.
    NotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

impl Reply {
    /// The reply for a connection to the destination that failed with `error`.
    pub fn for_connect_error(error: &io::Error) -> Reply {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
            io::ErrorKind::NetworkUnreachable => Reply::NetworkUnreachable,
            io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => Reply::HostUnreachable,
            _ => Reply::GeneralFailure,
        }
    }
}

/// Reads the client's greeting and its request, and returns the destination of a CONNECT
/// request, which the caller answers with `reply`. Everything else ends in an error, after the
/// answer that RFC 1928 has for it:
/// - a greeting without method 0 gets `X'FF'` ("no acceptable methods");
/// - an address type other than IPv4, IPv6 and a name gets reply 8 whatever the command, because
///   the length of its address is unknown;
/// - another command than CONNECT gets reply 7, whatever its address;
/// - a CONNECT to a domain name gets reply 8, so the broker resolves nothing for the client;
/// - another version than 5, the end of the stream and `HANDSHAKE_TIMEOUT` get no answer.
///
/// The reserved byte of the request is ignored, as RFC 1928 gives it no meaning.
pub fn read_request(client: &TcpStream) -> io::Result<SocketAddr> {
    read_request_within(client, HANDSHAKE_TIMEOUT)
}

/// Sends `reply`. The bound address it names is always `0.0.0.0:0`, so the client learns none of
/// the host's addresses.
pub fn reply(client: &TcpStream, reply: Reply) -> io::Result<()> {
    send(client, &[VERSION, reply as u8, 0, IPV4, 0, 0, 0, 0, 0, 0])
}

fn read_request_within(client: &TcpStream, timeout: Duration) -> io::Result<SocketAddr> {
    let deadline = Instant::now() + timeout;
    // Greeting: VER NMETHODS METHODS
    let mut greeting = [0u8; 2];
    read_by(client, &mut greeting, deadline)?;
    let [version, count] = greeting;
    if version != VERSION {
        return Err(invalid("not a SOCKS5 greeting"));
    }
    let mut methods = [0u8; u8::MAX as usize];
    let methods = &mut methods[..usize::from(count)];
    read_by(client, methods, deadline)?;
    if !methods.contains(&NO_AUTHENTICATION) {
        send(client, &[VERSION, NO_ACCEPTABLE_METHOD])?;
        return Err(refused(
            "the client offers no method without authentication",
        ));
    }
    send(client, &[VERSION, NO_AUTHENTICATION])?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT. It is read whole before it is judged: a
    // socket closed with unread data ends with a reset, which can take the reply with it.
    let mut header = [0u8; 4];
    read_by(client, &mut header, deadline)?;
    let [version, command, _, kind] = header;
    if version != VERSION {
        return Err(invalid("not a SOCKS5 request"));
    }
    let destination = match kind {
        IPV4 => {
            let mut address = [0u8; 6];
            read_by(client, &mut address, deadline)?;
            let [a, b, c, d, high, low] = address;
            Some(SocketAddr::from((
                Ipv4Addr::new(a, b, c, d),
                u16::from_be_bytes([high, low]),
            )))
        }
        IPV6 => {
            let mut address = [0u8; 18];
            read_by(client, &mut address, deadline)?;
            let (ip, port) = address.split_at(16);
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(ip).expect("16 bytes"));
            Some(SocketAddr::from((
                ip,
                u16::from_be_bytes([port[0], port[1]]),
            )))
        }
        DOMAIN_NAME => {
            let mut length = [0u8; 1];
            read_by(client, &mut length, deadline)?;
            let mut name_and_port = [0u8; u8::MAX as usize + 2];
            read_by(
                client,
                &mut name_and_port[..usize::from(length[0]) + 2],
                deadline,
            )?;
            None
        }
        // The length of an unknown address is unknown too, so this one is answered unread.
        _ => {
            reply(client, Reply::AddressTypeNotSupported)?;
            return Err(refused("unknown address type"));
        }
    };
    if command != CONNECT {
        reply(client, Reply::CommandNotSupported)?;
        return Err(refused("only CONNECT is supported"));
    }
    let Some(destination) = destination else {
        reply(client, Reply::AddressTypeNotSupported)?;
        return Err(refused("names are not resolved"));
    };
    client.set_read_timeout(None)?;
    Ok(destination)
}

/// Fills `buffer` from `client`, or fails once `deadline` has passed. The time left is set again
/// before each read, so a client that sends one byte at a time cannot extend it.
fn read_by(client: &TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut reader = client;
    let mut filled = 0;
    while filled < buffer.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the SOCKS5 handshake took too long",
            ));
        }
        client.set_read_timeout(Some(left))?;
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn send(client: &TcpStream, bytes: &[u8]) -> io::Result<()> {
    let mut writer = client;
    writer.write_all(bytes)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener};
    use std::thread;

    const GREETING: [u8; 3] = [5, 1, 0];
    const ACCEPTED: [u8; 2] = [5, 0];
    const CONNECT_V4: [u8; 10] = [5, 1, 0, 1, 192, 0, 2, 7, 0x01, 0xbb];

    /// A connected pair: the client's end, and the end the broker reads the handshake from.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    /// What the client received until the broker's end closed, and whether it closed with a
    /// normal end rather than a reset.
    #[derive(Debug)]
    struct Answer {
        bytes: Vec<u8>,
        clean: bool,
    }

    /// Sends `bytes` and ends the client's side, runs the handshake, and closes the broker's end
    /// as the broker does after a refusal.
    fn handshake(bytes: &[u8]) -> (io::Result<SocketAddr>, Answer) {
        let (mut client, server) = pair();
        client.write_all(bytes).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let result = read_request_within(&server, Duration::from_secs(5));
        drop(server);
        let mut answer = Answer {
            bytes: Vec::new(),
            clean: false,
        };
        let mut buffer = [0u8; 64];
        loop {
            match client.read(&mut buffer) {
                Ok(0) => {
                    answer.clean = true;
                    break;
                }
                Ok(read) => answer.bytes.extend_from_slice(&buffer[..read]),
                Err(_) => break,
            }
        }
        (result, answer)
    }

    fn reply_bytes(code: u8) -> [u8; 10] {
        [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
    }

    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn ipv6_request(command: u8, ip: &str, port: u16) -> Vec<u8> {
        let ip: Ipv6Addr = ip.parse().unwrap();
        concat(&[&[5, command, 0, 4], &ip.octets(), &port.to_be_bytes()])
    }

    fn name_request(command: u8, name: &[u8], port: u16) -> Vec<u8> {
        let length = u8::try_from(name.len()).unwrap();
        concat(&[&[5, command, 0, 3, length], name, &port.to_be_bytes()])
    }

    #[test]
    fn accepts_a_connect_to_an_ipv4_address() {
        let (result, answer) = handshake(&concat(&[&GREETING, &CONNECT_V4]));
        assert_eq!(result.unwrap(), "192.0.2.7:443".parse().unwrap());
        assert_eq!(answer.bytes, ACCEPTED);
    }

    #[test]
    fn accepts_a_connect_to_an_ipv6_address() {
        let request = ipv6_request(1, "2001:db8::1", 8080);
        let (result, answer) = handshake(&concat(&[&GREETING, &request]));
        assert_eq!(result.unwrap(), "[2001:db8::1]:8080".parse().unwrap());
        assert_eq!(answer.bytes, ACCEPTED);
    }

    /// Method 0 counts wherever the client lists it, also after 254 others.
    #[test]
    fn accepts_method_0_among_others() {
        let mut greeting = vec![5, 255];
        greeting.extend((1..=254).rev());
        greeting.push(0);
        let (result, answer) = handshake(&concat(&[&greeting, &CONNECT_V4]));
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(answer.bytes, ACCEPTED);
    }

    #[test]
    fn refuses_a_greeting_without_method_0() {
        let mut all_others = vec![5, 255];
        all_others.extend(1..=255);
        for greeting in [&[5, 0][..], &[5, 1, 2], &[5, 3, 1, 2, 0x80], &all_others] {
            let (result, answer) = handshake(greeting);
            assert!(result.is_err(), "{greeting:?}");
            assert_eq!(answer.bytes, [5, 0xff], "{greeting:?}");
            assert!(answer.clean, "{greeting:?}");
        }
    }

    /// Another command gets reply 7 whatever its address, after the whole request was read, so
    /// the reply is followed by a normal end and not by a reset.
    #[test]
    fn answers_other_commands_with_reply_7() {
        for command in [0, 2, 3, 4, 0xff] {
            let mut ipv4 = CONNECT_V4;
            ipv4[1] = command;
            for request in [
                ipv4.to_vec(),
                ipv6_request(command, "::1", 80),
                name_request(command, b"localhost", 80),
            ] {
                let (result, answer) = handshake(&concat(&[&GREETING, &request]));
                assert!(result.is_err());
                assert_eq!(
                    answer.bytes,
                    concat(&[&ACCEPTED, &reply_bytes(7)]),
                    "{request:?}"
                );
                assert!(answer.clean, "{request:?}");
            }
        }
    }

    /// A domain name would make the broker resolve names for the program, so it gets reply 8.
    #[test]
    fn answers_a_name_with_reply_8() {
        for name in [&b"localhost"[..], b"", &[b'a'; 255]] {
            let request = name_request(1, name, 443);
            let (result, answer) = handshake(&concat(&[&GREETING, &request]));
            assert!(result.is_err());
            assert_eq!(answer.bytes, concat(&[&ACCEPTED, &reply_bytes(8)]));
            assert!(answer.clean);
        }
    }

    #[test]
    fn answers_unknown_address_types_with_reply_8() {
        for kind in [0, 2, 5, 0xff] {
            let (result, answer) = handshake(&concat(&[&GREETING, &[5, 1, 0, kind]]));
            assert!(result.is_err());
            assert_eq!(
                answer.bytes,
                concat(&[&ACCEPTED, &reply_bytes(8)]),
                "{kind}"
            );
        }
    }

    #[test]
    fn closes_without_an_answer_on_another_version() {
        let (result, answer) = handshake(&[4, 1]);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(answer.bytes.is_empty());
        // A SOCKS4 request starts with version 4; nothing of it is taken for a greeting.
        let (result, answer) = handshake(&[4, 1, 0, 80, 127, 0, 0, 1, 0]);
        assert!(result.is_err());
        assert!(answer.bytes.is_empty());

        // Only the header of the request is sent: a socket closed with unread data resets, and
        // Windows then drops what the client had received.
        let (result, answer) = handshake(&concat(&[&GREETING, &[4, 1, 0, 1]]));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(answer.bytes, ACCEPTED);
    }

    /// The reserved byte has no meaning, so its value changes nothing.
    #[test]
    fn ignores_the_reserved_byte() {
        let mut request = CONNECT_V4;
        request[2] = 0x55;
        let (result, _) = handshake(&concat(&[&GREETING, &request]));
        assert_eq!(result.unwrap(), "192.0.2.7:443".parse().unwrap());
    }

    /// Input that ends anywhere before the request is complete is an error, never a request.
    #[test]
    fn refuses_truncated_input() {
        for full in [
            concat(&[&GREETING, &CONNECT_V4]),
            concat(&[&GREETING, &ipv6_request(1, "2001:db8::1", 80)]),
            concat(&[&[5, 3, 2, 1, 0], &CONNECT_V4]),
            concat(&[&GREETING, &name_request(1, b"example", 80)]),
        ] {
            for end in 0..full.len() {
                let (result, answer) = handshake(&full[..end]);
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{end}: {error}");
                assert!(
                    answer.bytes.is_empty() || answer.bytes == ACCEPTED,
                    "{end}: {answer:?}"
                );
            }
        }
    }

    /// The handshake reads exactly its own bytes: what follows the request in the same write is
    /// still there for the relay.
    #[test]
    fn leaves_data_behind_the_request_in_the_socket() {
        let (mut client, server) = pair();
        client
            .write_all(&concat(&[
                &GREETING,
                &CONNECT_V4,
                b"GET / HTTP/1.0\r\n\r\n",
            ]))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let destination = read_request_within(&server, Duration::from_secs(5)).unwrap();
        assert_eq!(destination, "192.0.2.7:443".parse().unwrap());
        assert_eq!(server.read_timeout().unwrap(), None);
        let mut rest = Vec::new();
        (&server).read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"GET / HTTP/1.0\r\n\r\n");
    }

    #[test]
    fn a_silent_client_times_out() {
        let (_client, server) = pair();
        let started = Instant::now();
        let error = read_request_within(&server, Duration::from_millis(200)).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{error}"
        );
        assert!(
            elapsed >= Duration::from_millis(200) && elapsed < Duration::from_secs(2),
            "{elapsed:?}"
        );
    }

    /// A client that sends one byte at a time, each well within the timeout, still has only
    /// the timeout for the whole handshake.
    #[test]
    fn a_slow_client_has_one_timeout_for_the_whole_handshake() {
        let (client, server) = pair();
        let bytes = concat(&[&GREETING, &CONNECT_V4]);
        let sender = thread::spawn(move || {
            let mut client = client;
            for byte in bytes {
                if client.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(60));
            }
            client
        });
        let started = Instant::now();
        let result = read_request_within(&server, Duration::from_millis(300));
        let elapsed = started.elapsed();
        assert!(result.is_err(), "{result:?}");
        // Sending all 13 bytes takes 780 ms; the timeout ends the handshake long before.
        assert!(elapsed < Duration::from_millis(700), "{elapsed:?}");
        drop(server);
        drop(sender.join().unwrap());
    }

    /// The read that waits when the time runs out waits only for what is left of it.
    #[test]
    fn a_client_that_stops_sending_is_cut_off_at_the_deadline() {
        let (client, server) = pair();
        let sender = thread::spawn(move || {
            let mut client = client;
            thread::sleep(Duration::from_millis(800));
            let _ = client.write_all(&GREETING[..1]);
            client
        });
        let started = Instant::now();
        let result = read_request_within(&server, Duration::from_secs(1));
        let elapsed = started.elapsed();
        assert!(result.is_err(), "{result:?}");
        // A read with the whole timeout would have waited until 1.8 seconds.
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
        drop(server);
        drop(sender.join().unwrap());
    }

    #[test]
    fn the_default_timeout_is_ten_seconds() {
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    }

    /// What the handshake should make of `bytes` that a client sends whole before it ends its
    /// side, by RFC 1928 and the comment of `read_request`: the destination and the length of
    /// an accepted handshake, or the kind of error, and what the broker answers.
    #[derive(Debug, PartialEq)]
    struct Expected {
        outcome: Result<(SocketAddr, usize), io::ErrorKind>,
        answer: Vec<u8>,
    }

    fn expected(bytes: &[u8]) -> Expected {
        use io::ErrorKind::{InvalidData, UnexpectedEof, Unsupported};
        let end = |kind, answer: &[u8]| Expected {
            outcome: Err(kind),
            answer: answer.to_vec(),
        };
        let Some(&[version, count]) = bytes.get(..2) else {
            return end(UnexpectedEof, &[]);
        };
        if version != 5 {
            return end(InvalidData, &[]);
        }
        let header = 2 + usize::from(count);
        let Some(methods) = bytes.get(2..header) else {
            return end(UnexpectedEof, &[]);
        };
        if !methods.contains(&0) {
            return end(Unsupported, &[5, 0xff]);
        }
        let Some(&[version, command, _, kind]) = bytes.get(header..header + 4) else {
            return end(UnexpectedEof, &ACCEPTED);
        };
        if version != 5 {
            return end(InvalidData, &ACCEPTED);
        }
        let at = header + 4;
        let length = match (kind, bytes.get(at)) {
            (1, _) => 6,
            (4, _) => 18,
            (3, Some(&name)) => 1 + usize::from(name) + 2,
            (3, None) => return end(UnexpectedEof, &ACCEPTED),
            _ => return end(Unsupported, &concat(&[&ACCEPTED, &reply_bytes(8)])),
        };
        let Some(address) = bytes.get(at..at + length) else {
            return end(UnexpectedEof, &ACCEPTED);
        };
        if command != 1 {
            return end(Unsupported, &concat(&[&ACCEPTED, &reply_bytes(7)]));
        }
        let port = u16::from_be_bytes([address[length - 2], address[length - 1]]);
        let ip: std::net::IpAddr = match kind {
            1 => Ipv4Addr::from(<[u8; 4]>::try_from(&address[..4]).unwrap()).into(),
            4 => Ipv6Addr::from(<[u8; 16]>::try_from(&address[..16]).unwrap()).into(),
            _ => return end(Unsupported, &concat(&[&ACCEPTED, &reply_bytes(8)])),
        };
        Expected {
            outcome: Ok((SocketAddr::new(ip, port), at + length)),
            answer: ACCEPTED.to_vec(),
        }
    }

    /// A deterministic source of numbers (xorshift64*), so that a failure always reproduces.
    struct Numbers(u64);

    impl Numbers {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }

        fn bytes(&mut self, count: usize) -> Vec<u8> {
            (0..count).map(|_| self.next() as u8).collect()
        }
    }

    /// Random bytes, or a handshake that is valid or nearly so, then cut short, changed in one
    /// byte, or followed by more bytes.
    fn hostile_input(numbers: &mut Numbers) -> Vec<u8> {
        if numbers.below(4) == 0 {
            let length = numbers.below(40);
            let mut bytes = numbers.bytes(length);
            if let Some(first) = bytes.first_mut().filter(|_| numbers.below(2) == 0) {
                *first = 5;
            }
            return bytes;
        }
        let count = numbers.below(6);
        let mut methods = numbers.bytes(count);
        if numbers.below(4) != 0 {
            methods.push(0);
        }
        let command = [1, 1, 1, numbers.next() as u8][numbers.below(4)];
        let kind = [1, 3, 4, numbers.next() as u8][numbers.below(4)];
        let mut bytes = concat(&[&[5, methods.len() as u8], &methods, &[5, command, 0, kind]]);
        match kind {
            1 => bytes.extend(numbers.bytes(6)),
            4 => bytes.extend(numbers.bytes(18)),
            3 => {
                let name = numbers.below(256);
                bytes.push(name as u8);
                bytes.extend(numbers.bytes(name + 2));
            }
            _ => {
                let count = numbers.below(20);
                bytes.extend(numbers.bytes(count));
            }
        }
        match numbers.below(4) {
            0 => bytes.truncate(numbers.below(bytes.len() + 1)),
            1 => {
                let at = numbers.below(bytes.len());
                bytes[at] = numbers.next() as u8;
            }
            2 => {
                let count = 1 + numbers.below(32);
                bytes.extend(numbers.bytes(count));
            }
            _ => {}
        }
        bytes
    }

    /// Fuzz-style: hostile inputs, each sent whole and ended, give what the model says: the same
    /// destination or error, the same answer, and for an accepted handshake exactly the bytes
    /// behind it still in the socket. The broker's end ends with a half close before it closes,
    /// so the answer arrives also where a close with unread data would reset the connection.
    #[test]
    fn hostile_input_gets_what_the_protocol_says() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut numbers = Numbers(0x5eed_2026_1025_0002);
        for round in 0..2000 {
            let bytes = hostile_input(&mut numbers);
            let expected = expected(&bytes);
            let mut client = TcpStream::connect(address).unwrap();
            let (server, _) = listener.accept().unwrap();
            client.write_all(&bytes).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let result = read_request_within(&server, Duration::from_secs(5));
            let mut rest = Vec::new();
            if result.is_ok() {
                (&server).read_to_end(&mut rest).unwrap();
            }
            server.shutdown(Shutdown::Write).unwrap();
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).unwrap();
            let outcome = result
                .map(|destination| (destination, bytes.len() - rest.len()))
                .map_err(|error| error.kind());
            assert_eq!(
                Expected { outcome, answer },
                expected,
                "round {round}: {bytes:?}"
            );
            if let Ok((_, length)) = expected.outcome {
                assert_eq!(rest, bytes[length..], "round {round}: {bytes:?}");
            }
        }
    }

    #[test]
    fn replies_name_no_address_of_the_host() {
        let codes = [
            (Reply::Succeeded, 0),
            (Reply::GeneralFailure, 1),
            (Reply::NotAllowed, 2),
            (Reply::NetworkUnreachable, 3),
            (Reply::HostUnreachable, 4),
            (Reply::ConnectionRefused, 5),
            (Reply::CommandNotSupported, 7),
            (Reply::AddressTypeNotSupported, 8),
        ];
        for (code, byte) in codes {
            let (mut client, server) = pair();
            reply(&server, code).unwrap();
            drop(server);
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).unwrap();
            assert_eq!(answer, reply_bytes(byte), "{code:?}");
        }
    }

    #[test]
    fn a_failed_connect_gets_the_matching_reply() {
        for (kind, expected) in [
            (io::ErrorKind::ConnectionRefused, Reply::ConnectionRefused),
            (io::ErrorKind::NetworkUnreachable, Reply::NetworkUnreachable),
            (io::ErrorKind::HostUnreachable, Reply::HostUnreachable),
            (io::ErrorKind::TimedOut, Reply::HostUnreachable),
            (io::ErrorKind::PermissionDenied, Reply::GeneralFailure),
            (io::ErrorKind::AddrNotAvailable, Reply::GeneralFailure),
        ] {
            assert_eq!(
                Reply::for_connect_error(&io::Error::from(kind)),
                expected,
                "{kind:?}"
            );
        }
    }
}
