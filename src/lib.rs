//! [Query Protocol](https://wiki.vg/Query), used for querying the status of a minecraft server.

use std::convert::TryInto;
use std::io;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

mod error;

use error::{Error, ParseError};

#[derive(Debug)]
pub struct Querier {
    sock: UdpSocket,
    session_id: u32,
    last_token: Option<i32>,
    retries: Option<Retries>,
    buf: Vec<u8>,
}
#[derive(Copy, Clone, Debug)]
struct Retries {
    pub max: u64,
    pub current: u64,
}

impl Querier {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(addr)?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        Ok(Querier {
            sock,
            session_id: 0,
            last_token: None,
            retries: Some(Retries { max: 3, current: 0 }),
            buf: vec![0; 1024],
        })
    }

    fn generate_new_session_id(&mut self) {
        self.session_id = self.session_id.wrapping_add(1);
    }

    fn should_retry(&mut self) -> bool {
        if let Some(ref mut retries) = self.retries {
            retries.current += 1;
            retries.max > retries.current
        } else {
            true
        }
    }

    fn reset_retry_counter(&mut self) {
        if let Some(ref mut retries) = self.retries {
            retries.current = 0;
        }
    }

    pub fn set_max_retries(&mut self, max_retries: Option<u64>) {
        if max_retries == Some(0) {
            panic!("set_max_retries called with max_retries == Some(0)");
        }
        self.retries = max_retries.map(|max| Retries { max, current: 0 });
    }

    pub fn max_retries(&self) -> Option<u64> {
        self.retries.map(|r| r.max)
    }

    pub fn set_timeout(&mut self, dur: Duration) -> Result<(), io::Error> {
        self.sock.set_read_timeout(Some(dur))
    }

    pub fn timeout(&self) -> Result<Duration, io::Error> {
        self.sock.read_timeout().map(Option::unwrap)
    }

    fn handshake(&mut self) -> Result<i32, Error> {
        let request = {
            let mut request = [0xfe, 0xfd, 0x09, 0x00, 0x00, 0x00, 0x00];
            request[3..].copy_from_slice(&self.session_id.to_be_bytes());
            request
        };

        let mut buf = [0; 17];

        loop {
            self.sock.send(&request)?;
            let len = match self.sock.recv(&mut buf) {
                Ok(len) => len,
                Err(e) => {
                    use io::ErrorKind::*;
                    if [WouldBlock, TimedOut].contains(&e.kind()) && self.should_retry() {
                        continue;
                    }
                    self.reset_retry_counter();
                    return Err(e.into());
                }
            };

            self.reset_retry_counter();

            match buf.get(0).copied() {
                Some(9) => {}
                Some(got) => return Err(ParseError::InvalidType { expected: 9, got }.into()),
                None => return Err(ParseError::UnexpectedEndOfData.into()),
            }
            match buf.get(1..5) {
                Some(session) if session == self.session_id.to_be_bytes() => {}
                Some(got_bytes) => {
                    let got = u32::from_be_bytes(got_bytes.try_into().unwrap());
                    return Err(ParseError::SessionIdMismatch {
                        expected: self.session_id,
                        got,
                    }
                    .into());
                }
                None => return Err(ParseError::UnexpectedEndOfData.into()),
            }

            if len < 6 || buf[len - 1] != 0 {
                return Err(ParseError::UnexpectedEndOfData.into());
            }

            let token_str = std::str::from_utf8(&buf[5..len - 1]).map_err(|err| {
                ParseError::PartParseFailed {
                    bytes: buf[5..len - 1].to_owned(),
                    ty: "i32",
                    source: Some(Box::new(err)),
                }
            })?;
            let token = token_str
                .parse::<i32>()
                .map_err(|err| ParseError::PartParseFailed {
                    bytes: buf[5..len - 1].to_owned(),
                    ty: "i32",
                    source: Some(Box::new(err)),
                })?;

            return Ok(token);
        }
    }

    fn stat<BUF, OUT>(&mut self) -> Result<OUT, Error>
    where
        BUF: AsMut<[u8]> + Default,
        OUT: ParseDatagram,
    {
        let mut token = self.last_token.ok_or(()).or_else(|_| self.handshake())?;

        let mut request = <BUF>::default();
        let request = request.as_mut();
        request[0] = 0xfe;
        request[1] = 0xfd;

        loop {
            request[3..7].copy_from_slice(&self.session_id.to_be_bytes());
            request[7..11].copy_from_slice(&token.to_be_bytes());
            self.sock.send(&*request)?;
            let len = match self.sock.recv(&mut self.buf[..]) {
                Ok(len) => len,
                Err(e) => {
                    use io::ErrorKind::*;
                    if [WouldBlock, TimedOut].contains(&e.kind()) && self.should_retry() {
                        self.generate_new_session_id();
                        self.last_token = None;
                        token = self.handshake()?;
                        continue;
                    }
                    self.reset_retry_counter();
                    return Err(e.into());
                }
            };
            self.reset_retry_counter();
            self.last_token = Some(token);
            println!("{:?}", &self.buf[..len]);
            return Ok(<OUT>::parse_datagram(
                Some(self.session_id),
                &self.buf[..len],
            )?);
        }
    }

    pub fn basic_stat(&mut self) -> Result<BasicStat, Error> {
        self.stat::<[u8; 11], BasicStat>()
    }

    pub fn full_stat(&mut self) -> Result<FullStat, Error> {
        self.stat::<[u8; 15], FullStat>()
    }
}

#[derive(Clone, Debug)]
pub struct BasicStat {
    buf: Vec<u8>,
    motd_end: usize,
    gametype_end: usize,
    num_players: u64,
    max_players: u64,
    host_ip: IpAddr,
    host_port: u16,
}

impl BasicStat {
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse_datagram(None, bytes)
    }

    pub fn motd(&self) -> &[u8] {
        &self.buf[..self.motd_end]
    }

    pub fn gametype(&self) -> &[u8] {
        &self.buf[self.motd_end..self.gametype_end]
    }

    pub fn map(&self) -> &[u8] {
        &self.buf[self.gametype_end..]
    }

    pub fn num_players(&self) -> u64 {
        self.num_players
    }

    pub fn max_players(&self) -> u64 {
        self.max_players
    }

    pub fn host_port(&self) -> u16 {
        self.host_port
    }

    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }
}

impl ParseDatagram for BasicStat {
    fn parse_datagram(session_id: Option<u32>, datagram: &[u8]) -> Result<Self, ParseError> {
        if datagram.len() < 13 {
            return Err(ParseError::TooShort);
        }
        let (header, body) = datagram.split_at(5);
        if header[0] != 0 {
            return Err(ParseError::InvalidType {
                expected: 0,
                got: header[0],
            });
        }
        if let Some(id) = session_id {
            let got_id = u32::from_be_bytes(datagram[1..5].try_into().unwrap());
            if id != got_id {
                return Err(ParseError::SessionIdMismatch {
                    expected: id,
                    got: got_id,
                });
            }
        }

        let mut result_buf = vec![];
        let mut body_iter = body.split(|&b| b == 0);

        let mut end_indices = [0; 2];
        let mut last_end_index = 0;
        for end_index in end_indices.iter_mut() {
            let content = body_iter.next().ok_or(ParseError::UnexpectedEndOfData)?;
            result_buf.extend_from_slice(content);
            *end_index = last_end_index + content.len();
            last_end_index += content.len();
        }
        result_buf.extend_from_slice(body_iter.next().ok_or(ParseError::UnexpectedEndOfData)?);

        let mut players = [0; 2];
        for player in &mut players {
            let player_bytes = body_iter.next().ok_or(ParseError::UnexpectedEndOfData)?;
            let player_str =
                std::str::from_utf8(player_bytes).map_err(|err| ParseError::PartParseFailed {
                    bytes: player_bytes.to_owned(),
                    ty: "u64",
                    source: Some(Box::new(err)),
                })?;
            *player = player_str
                .parse()
                .map_err(|err| ParseError::PartParseFailed {
                    bytes: player_bytes.to_owned(),
                    ty: "u64",
                    source: Some(Box::new(err)),
                })?;
        }

        let port_ip = body_iter.next().ok_or(ParseError::UnexpectedEndOfData)?;
        if port_ip.len() < 3 {
            return Err(ParseError::PartParseFailed {
                bytes: port_ip.to_owned(),
                ty: "Little-endian u16 and IpAddr Pair",
                source: None,
            });
        }
        let host_port = u16::from_le_bytes(port_ip[..2].try_into().unwrap());
        let host_ip_str =
            std::str::from_utf8(&port_ip[2..]).map_err(|err| ParseError::PartParseFailed {
                bytes: port_ip[2..].to_owned(),
                ty: "IpAddr",
                source: Some(Box::new(err)),
            })?;
        let host_ip = host_ip_str
            .parse()
            .map_err(|err| ParseError::PartParseFailed {
                bytes: port_ip[2..].to_owned(),
                ty: "IpAddr",
                source: Some(Box::new(err)),
            })?;

        Ok(BasicStat {
            buf: result_buf,
            motd_end: end_indices[0],
            gametype_end: end_indices[1],
            num_players: players[0],
            max_players: players[1],
            host_port,
            host_ip,
        })
    }
}

#[derive(Clone, Debug)]
pub struct FullStat {
    buf: Vec<u8>,
    hostname_end: usize,
    gametype_end: usize,
    gameid_end: usize,
    version_end: usize,
    plugins_end: usize,
    map_end: usize,
    num_players: u64,
    max_players: u64,
    host_port: u16,
    host_ip: IpAddr,
    player_ends: Vec<usize>,
}

impl FullStat {
    pub fn motd(&self) -> &[u8] {
        self.hostname()
    }

    pub fn hostname(&self) -> &[u8] {
        &self.buf[..self.hostname_end]
    }

    pub fn gametype(&self) -> &[u8] {
        &self.buf[self.hostname_end..self.gametype_end]
    }

    pub fn gameid(&self) -> &[u8] {
        &self.buf[self.gametype_end..self.gameid_end]
    }

    pub fn version(&self) -> &[u8] {
        &self.buf[self.gameid_end..self.version_end]
    }

    pub fn plugins(&self) -> &[u8] {
        &self.buf[self.version_end..self.plugins_end]
    }

    pub fn map(&self) -> &[u8] {
        &self.buf[self.plugins_end..self.map_end]
    }

    pub fn reported_num_players(&self) -> u64 {
        self.num_players
    }

    pub fn num_players(&self) -> usize {
        self.player_ends.len()
    }

    pub fn max_players(&self) -> u64 {
        self.max_players
    }

    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    pub fn host_port(&self) -> u16 {
        self.host_port
    }

    pub fn player(&self, idx: usize) -> Option<&[u8]> {
        self.player_ends.get(idx).map(|&end| {
            let start = if idx == 0 {
                self.map_end
            } else {
                self.player_ends[idx - 1]
            };
            &self.buf[start..end]
        })
    }
}

impl ParseDatagram for FullStat {
    fn parse_datagram(session_id: Option<u32>, datagram: &[u8]) -> Result<Self, ParseError> {
        if datagram.len() < 16 {
            return Err(ParseError::TooShort);
        }
        if datagram[0] != 0 {
            return Err(ParseError::InvalidType {
                expected: 0,
                got: datagram[0],
            });
        }
        if let Some(id) = session_id {
            let got_id = u32::from_be_bytes(datagram[1..5].try_into().unwrap());
            if id != got_id {
                return Err(ParseError::SessionIdMismatch {
                    expected: id,
                    got: got_id,
                });
            }
        }

        let mut buf = Vec::new();

        let mut idx = 16;
        let mut kv_iter = datagram[idx..]
            .split(|&b| b == 0)
            .inspect(|&s| idx += s.len() + 1);
        let mut ends = [0; 6];

        macro_rules! parse_kv {
            ($expected_key:expr, $do_with_value:expr) => {{
                let key = kv_iter.next();
                if key != Some($expected_key) {
                    if let Some(key) = key {
                        return Err(ParseError::UnexpectedKey {
                            expected: $expected_key,
                            got: key.to_owned(),
                        });
                    } else {
                        return Err(ParseError::UnexpectedEndOfData);
                    }
                }
                let value = kv_iter.next();
                if let Some(value) = value {
                    $do_with_value(value)
                } else {
                    return Err(ParseError::UnexpectedEndOfData);
                }
            }};
            ($expected_key:expr, APPEND_TO_BUF, $idx:expr) => {
                parse_kv!($expected_key, |value| {
                    buf.copy_from_slice(value);
                    ends[$idx] = buf.len();
                })
            };
            ($expected_key:expr, PARSE_AS, $tgt:ty, $description:expr) => {
                parse_kv!($expected_key, |value| {
                    std::str::from_utf8(value)
                        .map_err(|err| ParseError::PartParseFailed {
                            bytes: value.to_owned(),
                            ty: $description,
                            source: Some(Box::new(err)),
                        })
                        .and_then(|s| {
                            s.parse::<$tgt>()
                                .map_err(|err| ParseError::PartParseFailed {
                                    bytes: value.to_owned(),
                                    ty: $description,
                                    source: Some(Box::new(err)),
                                })
                        })
                })
            };
        }

        parse_kv!(b"hostname", APPEND_TO_BUF, 0);
        parse_kv!(b"gametype", APPEND_TO_BUF, 1);
        parse_kv!(b"game_id", APPEND_TO_BUF, 2);
        parse_kv!(b"version", APPEND_TO_BUF, 3);
        parse_kv!(b"plugins", APPEND_TO_BUF, 4);
        parse_kv!(b"map", APPEND_TO_BUF, 5);

        let num_players = parse_kv!(b"numplayers", PARSE_AS, u64, "u64")?;
        let max_players = parse_kv!(b"maxplayers", PARSE_AS, u64, "u64")?;
        let host_port = parse_kv!(b"hostport", PARSE_AS, u16, "u16")?;
        let host_ip = parse_kv!(b"hostip", PARSE_AS, IpAddr, "IpAddr")?;

        match kv_iter.next() {
            Some(b"") => {}
            Some(got) => {
                return Err(ParseError::UnexpectedKey {
                    expected: b"",
                    got: got.to_owned(),
                })
            }
            None => return Err(ParseError::UnexpectedEndOfData),
        }

        let mut player_ends = Vec::with_capacity(num_players as usize);
        idx += 10;
        let mut empty_player_found = false;
        let players_iter = datagram[idx..].split(|&b| b == 0);
        for player in players_iter {
            if player == b"" {
                empty_player_found = true;
                break;
            }
            buf.copy_from_slice(player);
            player_ends.push(buf.len());
        }
        if !empty_player_found {
            return Err(ParseError::UnexpectedEndOfData);
        }

        Ok(FullStat {
            buf,
            hostname_end: ends[0],
            gametype_end: ends[1],
            gameid_end: ends[2],
            version_end: ends[3],
            plugins_end: ends[4],
            map_end: ends[5],
            num_players,
            max_players,
            host_port,
            host_ip,
            player_ends,
        })
    }
}

trait ParseDatagram: Sized {
    fn parse_datagram(session_id: Option<u32>, datagram: &[u8]) -> Result<Self, ParseError>;
}
