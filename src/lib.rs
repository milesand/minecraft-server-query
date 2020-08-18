//! [Query Protocol](https://wiki.vg/Query), used for querying the status of a minecraft server.

use std::convert::{TryFrom};
use std::io;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};

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
        let sock = UdpSocket::bind("0.0.0.0:11047")?;
        sock.connect(addr)?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        Ok(Querier {
            sock,
            session_id: 307,
            last_token: None,
            retries: Some(Retries { max: 3, current: 0 }),
            buf: vec![0; 1024],
        })
    }

    fn generate_new_session_id(&mut self) {
        // TODO: make this do something
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
                    if [WouldBlock, TimedOut].contains(&e.kind())
                        && self.should_retry()
                    {
                        continue;
                    }
                    self.reset_retry_counter();
                    return Err(e.into());
                }
            };

            self.reset_retry_counter();

            match buf.get(0).copied() {
                Some(9) => {},
                _ => return Err(ParseError::Unspecified.into()),
            }
            match buf.get(1..5) {
                Some(session) if session == self.session_id.to_be_bytes() => {},
                _ => return Err(ParseError::Unspecified.into()),
            }

            let token = if len >= 6 && buf[len - 1] == 0 { Ok(()) } else { Err(()) }
                .and_then(|_| {
                    std::str::from_utf8(&buf[5..len - 1]) .map_err(|_| ())
                })
                .and_then(|s| {
                    s.parse::<i32>().map_err(|_| ())
                })
                .map_err(|_| ParseError::Unspecified)?;

            return Ok(token);
        }
    }

    pub fn basic_stat(&mut self) -> Result<BasicStat, Error> {
        let mut token = self.last_token.ok_or(()).or_else(|_| self.handshake())?;

        let mut request = [0; 11];
        request[0] = 0xfe;
        request[1] = 0xfd;

        loop {
            request[3..7].copy_from_slice(&self.session_id.to_be_bytes());
            request[7..11].copy_from_slice(&token.to_be_bytes());
            self.sock.send(&request)?;
            let len = match self.sock.recv(&mut self.buf[..]) {
                Ok(len) => len,
                Err(e) => {
                    use io::ErrorKind::*;
                    if [WouldBlock, TimedOut].contains(&e.kind())
                        && self.should_retry()
                    {
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
            return Ok(BasicStat::parse_bytes(self.session_id, &self.buf[..len])?);
        }
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
    fn parse_bytes(session_id: u32, buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 13 {
            return Err(ParseError::Unspecified);
        }
        let (header, body) = buf.split_at(5);
        if header[0] != 0 {
            return Err(ParseError::Unspecified);
        }
        if header[1..5] != session_id.to_be_bytes() {
            return Err(ParseError::Unspecified);
        }
    
        let mut result_buf = vec![];
        let mut body_iter = body.split(|&b| b == 0);
    
        let mut end_indices = [0; 2];
        let mut last_end_index = 0;
        for end_index in end_indices.iter_mut() {
            let content = body_iter.next().ok_or(ParseError::Unspecified)?;
            result_buf.extend_from_slice(content);
            *end_index = last_end_index + content.len();
            last_end_index += content.len();
        }
        result_buf.extend_from_slice(body_iter.next().ok_or(ParseError::Unspecified)?);
    
        let mut players = [0; 2];
        for player in &mut players {
            let player_bytes = body_iter.next().ok_or(ParseError::Unspecified)?;
            let player_str = std::str::from_utf8(player_bytes).map_err(|_| ParseError::Unspecified)?;
            *player = player_str.parse().map_err(|_| ParseError::Unspecified)?;
        }
    
        let port_ip = body_iter.next().ok_or(ParseError::Unspecified)?;
        if port_ip.len() < 3 {
            return Err(ParseError::Unspecified);
        }
        let host_port = u16::from_le_bytes(<[u8; 2]>::try_from(&port_ip[..2]).unwrap());
        let host_ip_str = std::str::from_utf8(&port_ip[2..]).map_err(|_| ParseError::Unspecified)?;
        let host_ip = host_ip_str.parse().map_err(|_| ParseError::Unspecified)?;
        
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