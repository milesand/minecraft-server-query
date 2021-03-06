//! **[Query Protocol](https://wiki.vg/Query)**, used for querying the status of a minecraft server.
//!
//! If you are looking for looking for a high-level component that handles the connection by itself, see [`Querier`].
//! If you want to handle IO by yourself, request constructors (like [`handshake_request`]) and response parsers
//! ([`parse_handshake_response`]) may be useful.
//!
//! # Examples
//!
//! ## Using [`Querier`]
//! ```no_run
//! use minecraft_server_query::Querier;
//! # use minecraft_server_query::error::Error;
//!
//! # fn main() -> Result<(), Error> {
//! let mut querier = Querier::connect("127.0.0.1:25565")?;
//!
//! let stat = querier.full_stat()?;
//!
//! for player in stat.players() {
//!     println!("{}", String::from_utf8_lossy(player));
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Using request constructors and parsers
//! ```no_run
//! use std::net::UdpSocket;
//! use minecraft_server_query::{
//!     handshake_request,
//!     parse_handshake_response,
//!     full_stat_request,
//!     parse_full_stat_response,
//!     SessionId,
//! };
//! # use minecraft_server_query::error::Error;
//!
//! # fn main() -> Result<(), Error> {
//! let sock = UdpSocket::bind("0.0.0.0:0")?;
//! sock.connect("127.0.0.1:25565");
//! let mut buf = vec![0u8; 1500];
//!
//! let handshake = handshake_request(SessionId::new());
//! sock.send(&handshake)?;
//! let len = sock.recv(&mut buf[..])?;
//! let (token, _id) = parse_handshake_response(&buf[..len])?;
//!
//! let full_stat = full_stat_request(SessionId::new(), token);
//! sock.send(&full_stat)?;
//! let len = sock.recv(&mut buf[..])?;
//! let (stat, _id) = parse_full_stat_response(&buf[..len])?;
//!
//! for player in stat.players() {
//!     println!("{}", String::from_utf8_lossy(player));
//! }
//! # Ok(())
//! # }
//! ```
//! [`Querier`]: ./struct.Querier.html
//! [`handshake_request`]: ./fn.handshake_request.html
//! [`parse_handshake_response`]: ./fn.parse_handshake_response.html

use std::convert::{TryFrom, TryInto};
use std::io;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::num::NonZeroU32;
use std::time::Duration;

pub mod error;
use error::{Error, ParseError};

mod session;
pub use session::SessionId;

const MAGIC: [u8; 2] = [0xfe, 0xfd];
const TYPE_HANDSHAKE: u8 = 0x09;
const TYPE_STAT: u8 = 0x00;

const MAX_IPADDR_LEN: usize = 45;

enum ParseByteError<E> {
    Utf8(std::str::Utf8Error),
    Parse(E),
}

// A helper for parsing data from bytes.
fn parse_bytes<T: std::str::FromStr>(bytes: &[u8]) -> Result<T, ParseByteError<T::Err>> {
    std::str::from_utf8(bytes)
        .map_err(ParseByteError::Utf8)
        .and_then(|s| s.parse::<T>().map_err(ParseByteError::Parse))
}

/// Constructs a handshake request that may be sent to the server.
pub fn handshake_request(id: SessionId) -> [u8; 7] {
    let mut datagram = [0; 7];
    datagram[0..2].copy_from_slice(&MAGIC);
    datagram[2] = TYPE_HANDSHAKE;
    datagram[3..7].copy_from_slice(&id.inner());
    datagram
}

/// Constructs a basic stat request that may be sent to the server.
pub fn basic_stat_request(id: SessionId, token: i32) -> [u8; 11] {
    let mut datagram = [0; 11];
    datagram[0..2].copy_from_slice(&MAGIC);
    datagram[2] = TYPE_STAT;
    datagram[3..7].copy_from_slice(&id.inner());
    datagram[7..11].copy_from_slice(&token.to_be_bytes());
    datagram
}

/// Constructs a full stat request that may be sent to the server.
pub fn full_stat_request(id: SessionId, token: i32) -> [u8; 15] {
    let mut datagram = [0; 15];
    datagram[0..2].copy_from_slice(&MAGIC);
    datagram[2] = TYPE_STAT;
    datagram[3..7].copy_from_slice(&id.inner());
    datagram[7..11].copy_from_slice(&token.to_be_bytes());
    // [11..15] works as padding. Per documentation, Minecraft distinguishes basic and full stat request by request length.
    datagram
}

// Check if this partial session id is a valid prefix of complete session id.
fn is_valid_partial_session_id(id: &[u8]) -> bool {
    debug_assert!(id.len() <= 3);
    if id.is_empty() {
        return true;
    }
    match std::str::from_utf8(id) {
        Ok(_) => true,
        Err(e) => {
            if e.error_len().is_some() {
                false
            } else if e.valid_up_to() == 2 && id.len() == 3 {
                id[2] < 0b11100000
            } else {
                true
            }
        }
    }
}

/// Parses the handshake response received from the server into a (Challenge Token, Session ID) pair.
pub fn parse_handshake_response(response: &[u8]) -> Result<(i32, SessionId), ParseError> {
    // handshake response datagram looks like this:
    // * Type (1 byte); should be 0x09
    // * Session ID (4 bytes)
    // * Challenge Token (Null-terminated string)
    // Where Challenge Token is a decimal string representation of 32-bit signed integer.

    let malformed = || ParseError::MalformedInput {
        requested_kind: "handshake response",
    };

    // Check Type
    if response.is_empty() {
        return Err(ParseError::UnexpectedEndOfInput);
    }
    if response[0] != TYPE_HANDSHAKE {
        return Err(malformed());
    }

    // Parse Session ID
    if response.len() < 5 {
        return Err(if is_valid_partial_session_id(&response[1..]) {
            ParseError::UnexpectedEndOfInput
        } else {
            malformed()
        });
    }
    let id_bytes = <[u8; 4]>::try_from(&response[1..5]).unwrap();
    let id = SessionId::try_from(id_bytes).map_err(|_| malformed())?;

    // Parse Challenge Token
    if response.len() == 5 {
        // The whole challenge token is missing; Input up until now was valid.
        return Err(ParseError::UnexpectedEndOfInput);
    }
    if response[response.len() - 1] != 0 {
        // Missing null terminator
        return Err(
            // Check if the remaining part looks like a valid prefix of i32;
            // that is, a single negative sign, or just i32.
            if (response.len() == 6 && response[5] == b'-')
                || parse_bytes::<i32>(&response[5..response.len()]).is_ok()
            {
                ParseError::UnexpectedEndOfInput
            } else {
                malformed()
            },
        );
    }

    let token = parse_bytes::<i32>(&response[5..response.len() - 1]).map_err(|_| malformed())?;

    Ok((token, id))
}

/// Parses the basic stat response received from the server into a (Stat result, Session ID) pair.
pub fn parse_basic_stat_response(response: &[u8]) -> Result<(BasicStat, SessionId), ParseError> {
    // handshake response datagram looks like this:
    // * Type (1 byte); should be 0x00
    // * Session ID (4 bytes)
    // * MOTD (Null-terminated string)
    // * Gametype (Null-terminated string)
    // * Map (Null-terminated string)
    // * Current number of players (Null-terminated string)
    // * Maximum number of players (Null-terminated string)
    // * Host port (Little endian, 16 bit)
    // * Host IP (Null-terminated string)
    //
    // Here we assume:
    // * Current/Maximum number of players can be parsed into `u32`
    //   * The Minecraft Wiki states that the maximum value `max-players` property can have is 2^31-1
    //     (for Java Edition), and for obvious reason it is never negative, so it seems okay to assume
    //     any valid player count will fall in the range covered by u32.
    // * Host IP can be parsed into `IpAddr`

    let malformed = || ParseError::MalformedInput {
        requested_kind: "basic stat response",
    };

    // Check Type
    if response.is_empty() {
        return Err(ParseError::UnexpectedEndOfInput);
    }
    if response[0] != TYPE_STAT {
        return Err(malformed());
    }

    // Parse Session ID
    if response.len() < 5 {
        return Err(if is_valid_partial_session_id(&response[1..]) {
            ParseError::UnexpectedEndOfInput
        } else {
            malformed()
        });
    }
    let id_bytes = <[u8; 4]>::try_from(&response[1..5]).unwrap();
    let id = SessionId::try_from(id_bytes).map_err(|_| malformed())?;

    // Parse the payload section.
    // Since the payload section is mostly null-terminated string, so we split the whole thing by null bytes and handle
    // each part.
    let mut body_iter = response[5..].split(|&b| b == 0);

    // MOTD, Gametype and Map sections are byte strings. Copy them into a single owned buffer, and manage the indices.
    let mut result_buf = vec![];
    // End indices for MOTD and Gametype; Map implicitly ends at the end of buffer, so no additional indice is needed.
    let mut end_indices = [0; 2];
    for end_index in end_indices.iter_mut() {
        // First iteration handles MOTD. Second handles Gametype.
        let content = body_iter.next().ok_or(ParseError::UnexpectedEndOfInput)?;
        result_buf.extend_from_slice(content);
        *end_index = result_buf.len();
    }
    // Handle Map.
    result_buf.extend_from_slice(body_iter.next().ok_or(ParseError::UnexpectedEndOfInput)?);

    // Current/Maximum number of player section.
    let mut players = [0; 2];
    for player in &mut players {
        let player_bytes = body_iter.next().ok_or(ParseError::UnexpectedEndOfInput)?;
        if player_bytes.is_empty() {
            if body_iter.next().is_some() {
                return Err(malformed());
            } else {
                return Err(ParseError::UnexpectedEndOfInput);
            }
        }
        *player = parse_bytes::<u32>(player_bytes).map_err(|_| malformed())?;
    }

    let port_ip = body_iter.next().ok_or(ParseError::UnexpectedEndOfInput)?;
    // Check for the existence of null terminator and end-of-input, before parsing port and ip.
    let should_be_some_empty = body_iter.next();
    let should_be_none = body_iter.next();
    if should_be_none.is_some() {
        return Err(malformed());
    }
    if let Some(bytes) = should_be_some_empty {
        if !bytes.is_empty() {
            return Err(malformed());
        }
    } else if port_ip.len() <= std::mem::size_of::<u16>() + MAX_IPADDR_LEN {
        // We've established that there's nothing behind port_ip in the input; it's the postfix.
        // So we need to check whether port_ip is a prefix of port-IpAddr pair. since all bytes are valid for port,
        // we don't have to care about it. But unfortunately, there's no easy way to check if host_ip is a prefix of
        // valid string representation of IpAddr. But the representation does have an upper bound: 45 bytes
        // (IPv4-Mapped IPv6 Address).
        // So we consider any byte string shorter than that a potentially-valid IpAddr, and anything longer to be
        // invalid.
        return Err(ParseError::UnexpectedEndOfInput);
    } else {
        return Err(malformed());
    }

    // Now that we've ensured that there is something(the null-terminator) behind port_ip, we can forget about
    // UnexpectedEndOfInput while parsing port_ip.

    let host_port = u16::from_le_bytes(port_ip[..2].try_into().unwrap());
    let host_ip_bytes = &port_ip[2..];
    let host_ip = parse_bytes::<IpAddr>(host_ip_bytes).map_err(|_| malformed())?;

    let stat = BasicStat {
        buf: result_buf.into_boxed_slice(),
        motd_end: end_indices[0],
        gametype_end: end_indices[1],
        num_players: players[0],
        max_players: players[1],
        host_port,
        host_ip,
    };

    Ok((stat, id))
}

/// Parses the full stat response received from the server into a (Stat result, Session ID) pair.
pub fn parse_full_stat_response(response: &[u8]) -> Result<(FullStat, SessionId), ParseError> {
    // handshake response datagram looks like this:
    // * Type (1 byte); should be 0x00
    // * Session ID (4 bytes)
    // * Padding (11 bytes)
    // * KV Section (Pairs of Null-terminated strings)
    // * Padding (10 bytes)
    // * Player list (Null-terminated strings)
    //
    // Here we make assumptions from parse_basic_stat, and:
    // * The keys appear in following order in KV Section: hostname, gametype, game_id, version, plugins, map,
    //   numplayers, maxplayers, hostport, hostip.
    // * hostport can be parsed into `u16`.

    let malformed = || ParseError::MalformedInput {
        requested_kind: "full stat response",
    };

    // Check Type
    if response.is_empty() {
        return Err(ParseError::UnexpectedEndOfInput);
    }
    if response[0] != TYPE_STAT {
        return Err(malformed());
    }

    // Parse Session ID
    if response.len() < 5 {
        return Err(if is_valid_partial_session_id(&response[1..]) {
            ParseError::UnexpectedEndOfInput
        } else {
            malformed()
        });
    }
    let id_bytes = <[u8; 4]>::try_from(&response[1..5]).unwrap();
    let id = SessionId::try_from(id_bytes).map_err(|_| malformed())?;

    // Check for existence of Padding
    if response.len() <= 16 {
        return Err(ParseError::UnexpectedEndOfInput);
    }

    let mut buf = Vec::new();

    // KV Section
    let mut kv_len = 0;
    let mut kv_iter = response[16..]
        .split(|&b| b == 0)
        // keep track of the length of KV section; 1 is for the null terminator.
        // Used to get index from which to start parsing again when we're done with KV section.
        .inspect(|&s| kv_len += s.len() + 1);

    macro_rules! parse_kv {
        ($expected_key:expr) => {{
            let key = kv_iter.next();
            if key != Some($expected_key) {
                match key {
                    Some(key) if !$expected_key.starts_with(key) || kv_iter.next().is_some() => {
                        return Err(malformed());
                    }
                    _ => {
                        return Err(ParseError::UnexpectedEndOfInput);
                    }
                }
            }
            let value = kv_iter.next();
            if let Some(value) = value {
                value
            } else {
                return Err(ParseError::UnexpectedEndOfInput);
            }
        }};
    }

    // Byte string values.
    let mut ends = [0; 6]; // End indices for byte string values copied into the buffer.
    for (&key, end_index) in [
        &b"hostname"[..],
        &b"gametype"[..],
        &b"game_id"[..],
        &b"version"[..],
        &b"plugins"[..],
        &b"map"[..],
    ]
    .iter()
    .zip(ends.iter_mut())
    {
        let value = parse_kv!(key);
        buf.extend_from_slice(value);
        *end_index = buf.len();
    }

    // Parsable values.
    macro_rules! parse_kv_to {
        ($key:expr, $ty:ty) => {
            parse_kv_to!($key, $ty, |_| false)
        };
        ($key:expr, $ty:ty, $is_malformed:expr) => {{
            let value_bytes = parse_kv!($key);
            parse_bytes::<$ty>(value_bytes).map_err(|err| {
                if let ParseByteError::Utf8(_) = err {
                    return malformed();
                }
                if kv_iter.next().is_some() || (!value_bytes.is_empty() && $is_malformed(value_bytes)) {
                    return malformed();
                }
                ParseError::UnexpectedEndOfInput
            })
        }};
    }
    let num_players = parse_kv_to!(b"numplayers", u32)?;
    let max_players = parse_kv_to!(b"maxplayers", u32)?;
    let host_port = parse_kv_to!(b"hostport", u16)?;
    let host_ip = parse_kv_to!(b"hostip", IpAddr, |bytes: &[u8]| bytes.len() >= MAX_IPADDR_LEN)?;

    // Check for the empty key.
    let empty_key = kv_iter.next().ok_or(ParseError::UnexpectedEndOfInput)?;
    if !empty_key.is_empty() {
        return Err(malformed());
    }

    let kv_end = 16 + kv_len;

    // Check padding.
    if response.len() < kv_end + 10 {
        return Err(ParseError::UnexpectedEndOfInput);
    }

    let player_section_start = kv_end + 10;
    println!("{}", player_section_start);

    // Player Section.
    let mut player_ends = Vec::new();
    let mut empty_player_found = false;
    let mut players_iter = response[player_section_start..].split(|&b| b == 0);
    for player in players_iter.by_ref() {
        if player.is_empty() {
            // Empty player == end of player section
            empty_player_found = true;
            break;
        }
        buf.extend_from_slice(player);
        player_ends.push(buf.len());
    }
    if !empty_player_found {
        return Err(ParseError::UnexpectedEndOfInput);
    }
    // Check for null terminator and end-of-input.
    let should_be_empty = players_iter.next().ok_or(ParseError::UnexpectedEndOfInput)?;
    if !should_be_empty.is_empty() || players_iter.next().is_some() {
        return Err(malformed());
    }

    let stat = FullStat {
        buf: buf.into_boxed_slice(),
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
        player_ends: player_ends.into_boxed_slice(),
    };
    Ok((stat, id))
}

type Parser<OUT> = fn(&[u8]) -> Result<(OUT, SessionId), ParseError>;

/// A Query client that can connect to and query a single Minecraft server.
///
/// `Querier` handles token caching, buffer resizing, timeouts and retrying. It will cache challenge tokens and reuse
/// them for future requests, and handle timeouts by retrying upto number of times set by the user.
///
/// This uses blocking IO.
#[derive(Debug)]
pub struct Querier {
    sock: UdpSocket,
    last_token: Option<i32>,
    max_retries: Option<NonZeroU32>,
    buf: Vec<u8>,
}

impl Querier {
    /// Constructs a `Querier` connected to given address.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(addr)?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        Ok(Querier {
            sock,
            last_token: None,
            max_retries: Some(NonZeroU32::new(3).unwrap()),
            buf: vec![0; 1500], // Ethernet MTU
        })
    }

    /// Set the number of handshake timeouts allowed before giving up.
    ///
    /// Setting this to `None` will make the Querier retry indefinitely on timeouts. This may cause the thread to block
    /// indefinitely, if connected to wrong address or the server is down.
    ///
    /// Defaults to `Some(3)`.
    ///
    /// # Panics
    ///
    /// Panics if `max_retires` is `Some(0)`.
    pub fn set_max_retries(&mut self, max_retries: Option<u32>) {
        assert_ne!(max_retries, Some(0));
        self.max_retries = max_retries.map(|nz| NonZeroU32::new(nz).unwrap());
    }

    /// The number of handshake timeouts allowed before giving up.
    pub fn max_retries(&self) -> Option<u32> {
        self.max_retries.map(NonZeroU32::get)
    }

    /// Set read timeout for underlying UDP socket. A Minecraft server sends no response to invalid requests, and
    /// tokens are invalidated every 30 seconds, so it is expected that a timeout occurs once every 30 seconds. Thus,
    /// ideally this should be set to minimum duration that still allows communication with the server. An `Err` is
    /// returned if the zero `Duration` is passed to this method.
    ///
    /// Defaults to 1 second.
    pub fn set_timeout(&mut self, dur: Duration) -> Result<(), io::Error> {
        self.sock.set_read_timeout(Some(dur))
    }

    /// Read timeout for underlying UDP socket.
    pub fn timeout(&self) -> Result<Duration, io::Error> {
        self.sock.read_timeout().map(Option::unwrap)
    }

    fn handshake(&mut self) -> Result<i32, Error> {
        let request = handshake_request(SessionId::new());

        let mut buf = [0; 17];
        let mut retries = 1;
        loop {
            self.sock.send(&request)?;
            let len = match self.sock.recv(&mut buf) {
                Ok(len) => len,
                Err(e) => {
                    match self.max_retries() {
                        Some(max_retries) if max_retries <= retries => {}
                        _ => {
                            use io::ErrorKind::*;
                            if [WouldBlock, TimedOut].contains(&e.kind()) {
                                retries += 1;
                                continue;
                            }
                        }
                    }
                    return Err(e.into());
                }
            };

            return parse_handshake_response(&buf[..len])
                .map(|(token, _)| token)
                .map_err(|e| e.into());
        }
    }

    fn stat<REQ, OUT>(
        &mut self,
        req: fn(SessionId, i32) -> REQ,
        parser: Parser<OUT>,
    ) -> Result<OUT, Error>
    where
        REQ: AsRef<[u8]>,
    {
        let mut token = self.last_token.ok_or(()).or_else(|_| self.handshake())?;

        loop {
            let request = req(SessionId::new(), token);
            self.sock.send(request.as_ref())?;
            let mut len = match self.sock.peek(&mut self.buf[..]) {
                Ok(len) => len,
                Err(e) => {
                    use io::ErrorKind::*;
                    if [WouldBlock, TimedOut].contains(&e.kind()) {
                        token = self.handshake()?;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            self.last_token = Some(token);

            loop {
                let ret = parser(&self.buf[..len]);

                match ret {
                    Ok((ret, _)) => {
                        self.sock.recv(&mut self.buf[..])?;
                        return Ok(ret);
                    }
                    Err(ParseError::UnexpectedEndOfInput) if len == self.buf.len() => {
                        self.buf.resize(self.buf.len() * 2, 0);
                        len = self.sock.peek(&mut self.buf[..])?;
                        continue;
                    }
                    Err(err) => {
                        self.sock.recv(&mut self.buf[..])?;
                        return Err(err.into());
                    }
                }
            }
        }
    }

    /// Perform a basic stat on the connected server.
    pub fn basic_stat(&mut self) -> Result<BasicStat, Error> {
        self.stat(basic_stat_request, parse_basic_stat_response)
    }

    /// Perform a full stat on the connected server.
    pub fn full_stat(&mut self) -> Result<FullStat, Error> {
        self.stat(full_stat_request, parse_full_stat_response)
    }
}

/// Result of basic stat.
#[derive(Clone, Debug)]
pub struct BasicStat {
    buf: Box<[u8]>,
    motd_end: usize,
    gametype_end: usize,
    num_players: u32,
    max_players: u32,
    host_ip: IpAddr,
    host_port: u16,
}

impl BasicStat {
    /// MOTD set on the server. This may contain color and formatting codes, resulting in non UTF-8 sequence.
    pub fn motd(&self) -> &[u8] {
        &self.buf[..self.motd_end]
    }

    /// Game type of the server. Typically `b"SMP"`.
    pub fn gametype(&self) -> &[u8] {
        &self.buf[self.motd_end..self.gametype_end]
    }

    /// Name of the map of the server.
    pub fn map(&self) -> &[u8] {
        &self.buf[self.gametype_end..]
    }

    /// Number of current players.
    pub fn num_players(&self) -> u32 {
        self.num_players
    }

    /// Maximum number of players allowed on the server.
    pub fn max_players(&self) -> u32 {
        self.max_players
    }

    /// Port number the server is bound to.
    pub fn host_port(&self) -> u16 {
        self.host_port
    }

    /// IP address the server is bound to. Note that this is the address server bound itself to, and not the address
    /// players should connect to to join the server.
    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }
}

/// Result of full stat.
#[derive(Clone, Debug)]
pub struct FullStat {
    buf: Box<[u8]>,
    hostname_end: usize,
    gametype_end: usize,
    gameid_end: usize,
    version_end: usize,
    plugins_end: usize,
    map_end: usize,
    num_players: u32,
    max_players: u32,
    host_port: u16,
    host_ip: IpAddr,
    player_ends: Box<[usize]>,
}

impl FullStat {
    /// MOTD set on the server. This may contain color and formatting codes, resulting in non UTF-8 sequence.
    pub fn motd(&self) -> &[u8] {
        self.hostname()
    }

    /// Alias of `motd`.
    pub fn hostname(&self) -> &[u8] {
        &self.buf[..self.hostname_end]
    }

    /// Game type of the server. According to reverse-engineered documentation, hardcoded to `b"SMP"`.
    pub fn gametype(&self) -> &[u8] {
        &self.buf[self.hostname_end..self.gametype_end]
    }

    /// Game ID of the server. According to reverse-engineered documentation, hardcoded to `b"MINECRAFT"`.
    pub fn gameid(&self) -> &[u8] {
        &self.buf[self.gametype_end..self.gameid_end]
    }

    /// The server's Minecraft version.
    pub fn version(&self) -> &[u8] {
        &self.buf[self.gameid_end..self.version_end]
    }

    /// List of plugins running on the server, not used for vanilla servers.
    ///
    /// Bukkit uses the following format:
    /// `[SERVER_MOD_NAME[: PLUGIN_NAME(; PLUGIN_NAME...)]]`
    pub fn plugins(&self) -> &[u8] {
        &self.buf[self.version_end..self.plugins_end]
    }

    /// Name of the map of the server.
    pub fn map(&self) -> &[u8] {
        &self.buf[self.plugins_end..self.map_end]
    }

    /// Number of current players, reported by the server. Practically this should equal `num_players`. The server
    /// reports the number of players and the list of players separately, so it may be possible for the two to vary.
    pub fn reported_num_players(&self) -> u32 {
        self.num_players
    }

    /// Number of players returned in the player list. Practically this should equal `num_players`. The server reports
    /// the number of players and the list of players separately, so it may be possible for the two to vary.
    pub fn num_players(&self) -> usize {
        self.player_ends.len()
    }

    /// Maximum number of players allowed on the server.
    pub fn max_players(&self) -> u32 {
        self.max_players
    }

    /// IP address the server is bound to. Note that this is the address server bound itself to, and not the address
    /// players should connect to to join the server.
    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    /// Port number the server is bound to.
    pub fn host_port(&self) -> u16 {
        self.host_port
    }

    /// Index the player list and returns the name. Returns `None` if the index was out of range.
    pub fn get_player(&self, idx: usize) -> Option<&[u8]> {
        self.player_ends.get(idx).map(|&end| {
            let start = if idx == 0 {
                self.map_end
            } else {
                self.player_ends[idx - 1]
            };
            &self.buf[start..end]
        })
    }

    /// Returns an iterator over the list of players.
    pub fn players(&self) -> Players {
        Players {
            buf: &*self.buf,
            start: self.map_end,
            ends: self.player_ends.iter(),
        }
    }
}

/// An iterator over the list of players.
pub struct Players<'a> {
    buf: &'a [u8],
    start: usize,
    ends: std::slice::Iter<'a, usize>,
}

impl<'a> Iterator for Players<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.ends.next().map(|&end| {
            let start = self.start;
            self.start = end;
            &self.buf[start..end]
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[macro_use]
    mod test_helper_macros {
        macro_rules! handshake_request_tests {
            ($(($input:expr => $expected:expr, $test_name:ident)),+$(,)?) => {
                $(
                    #[test]
                    fn $test_name() {
                        let input = SessionId::try_from_bytes($input).unwrap();
                        let got = handshake_request(input);
                        assert_eq!(got, $expected);
                    }
                )+
            }
        }

        macro_rules! partial_test {
            ($input:expr, $test_name:ident, $parser_fn:expr) => {
                #[test]
                fn $test_name() {
                    let complete_input = &$input[..];
                    for partial_len in 0..complete_input.len() {
                        let got = $parser_fn(&complete_input[..partial_len]);
                        if let Err(ParseError::UnexpectedEndOfInput) = got {
                            continue;
                        }
                        panic!(
                            "Parsing {:?} (Length {}) returned {:?}",
                            &complete_input[..partial_len],
                            partial_len,
                            got
                        );
                    }
                }
            };
        }

        macro_rules! handshake_response_tests {
            ($(($input:expr => ($expected_token:expr, $expected_id:expr), $valid_test:ident, $partial_test:ident)),+$(,)?) => {
                $(
                    #[test]
                    fn $valid_test() {
                        let input = &$input[..];
                        match parse_handshake_response(&input[..]) {
                            Ok((got_token, got_id)) => {
                                assert_eq!(got_token, $expected_token);
                                assert_eq!(got_id, SessionId::try_from_bytes($expected_id).unwrap());
                            },
                            Err(e) => panic!("Parsing {:?} returned Error: {:?}", $input, e),
                        }
                    }

                    partial_test!($input, $partial_test, parse_handshake_response);
                )+
            };
        }

        macro_rules! handshake_malformed_response_tests {
            ($(($input:expr, $test_name:ident)),+$(,)?) => {
                $(
                    #[test]
                    fn $test_name() {
                        let input = &$input[..];
                        let got = parse_handshake_response(input);
                        assert_eq!(
                            got,
                            Err(ParseError::MalformedInput {
                                requested_kind: "handshake response",
                            }),
                            "Parsing {:?}: got unexpected result {:?}",
                            input,
                            got,
                        )
                    }
                )+
            }
        }

        macro_rules! basic_stat_request_tests {
            ($((($id:expr, $token:expr) => $expected:expr, $test_name:ident)),+$(,)?) => {
                $(
                    #[test]
                    fn $test_name() {
                        let id = SessionId::try_from_bytes($id).unwrap();
                        let token = $token;
                        let got = basic_stat_request(id, token);
                        assert_eq!(got, $expected);
                    }
                )+
            }
        }

        macro_rules! basic_stat_response_tests {
            ($(($input:expr => (
                $expected_motd:expr,
                $expected_gametype:expr,
                $expected_map:expr,
                $expected_num_players:expr,
                $expected_max_players:expr,
                $expected_port:expr,
                $expected_ip:expr,
                $expected_id:expr,
            ), $valid_test:ident, $partial_test:ident)),+$(,)?) => {
                $(
                    #[test]
                    fn $valid_test() {
                        let input = &$input[..];
                        match parse_basic_stat_response(input) {
                            Ok((got_stat, got_id)) => {
                                assert_eq!(got_stat.motd(), &$expected_motd[..]);
                                assert_eq!(got_stat.gametype(), &$expected_gametype[..]);
                                assert_eq!(got_stat.map(), &$expected_map[..]);
                                assert_eq!(got_stat.num_players(), $expected_num_players);
                                assert_eq!(got_stat.max_players(), $expected_max_players);
                                assert_eq!(got_stat.host_port(), $expected_port);
                                assert_eq!(got_stat.host_ip(), $expected_ip.parse::<IpAddr>().unwrap());
                                assert_eq!(got_id, SessionId::try_from_bytes($expected_id).unwrap());
                            },
                            Err(e) => panic!("Parsing {:?} returned Error: {:?}", input, e),
                        }
                    }

                    partial_test!($input, $partial_test, parse_basic_stat_response);
                )+
            };
        }

        macro_rules! full_stat_response_tests {
            ($(($input:expr => (
                $expected_motd:expr,
                $expected_gametype:expr,
                $expected_gameid:expr,
                $expected_version:expr,
                $expected_plugins:expr,
                $expected_map:expr,
                $expected_num_players:expr,
                $expected_max_players:expr,
                $expected_port:expr,
                $expected_ip:expr,
                [$($expected_player:expr),*],
                $expected_id:expr
            ), $valid_test:ident, $partial_test:ident)),+$(,)?) => {
                $(
                    #[test]
                    fn $valid_test() {
                        let input = &$input[..];
                        match parse_full_stat_response(input) {
                            Ok((got_stat, got_id)) => {
                                assert_eq!(got_stat.motd(), &$expected_motd[..]);
                                assert_eq!(got_stat.gametype(), &$expected_gametype[..]);
                                assert_eq!(got_stat.gameid(), &$expected_gameid[..]);
                                assert_eq!(got_stat.version(), &$expected_version[..]);
                                assert_eq!(got_stat.plugins(), &$expected_plugins[..]);
                                assert_eq!(got_stat.map(), &$expected_map[..]);
                                assert_eq!(got_stat.reported_num_players(), $expected_num_players);
                                assert_eq!(got_stat.max_players(), $expected_max_players);
                                assert_eq!(got_stat.host_port(), $expected_port);
                                assert_eq!(got_stat.host_ip(), $expected_ip.parse::<IpAddr>().unwrap());
                                let mut got_players = got_stat.players();
                                $(
                                    assert_eq!(got_players.next(), Some(&$expected_player[..]));
                                )*
                                assert!(got_players.next().is_none());
                                assert_eq!(got_id, SessionId::try_from_bytes($expected_id).unwrap());
                            },
                            Err(e) => {
                                panic!("Parsing {:?} returned {:?}", input, e);
                            },
                        }
                    }

                    partial_test!($input, $partial_test, parse_full_stat_response);
                )+
            }
        }
    }

    handshake_request_tests![
        ([0, 0, 0, 0] => [0xfe, 0xfd, 0x09, 0, 0, 0, 0], test_handshake_request_1),
        ([0, 0, 0, 1] => [0xfe, 0xfd, 0x09, 0, 0, 0, 1], test_handshake_request_2),
        ([7, 6, 5, 64] => [0xfe, 0xfd, 0x09, 7, 6, 5, 64], test_handshake_request_3),
    ];

    handshake_response_tests![
        (
            b"\x09\x00\x00\x00\x009513307\0" => (9513307, [0, 0, 0, 0]),
            test_handshake_response_ok_1,
            test_handshake_response_partial_1
        ),
        (
            b"\x09\x00\x00\x00\x01-1213578601\0" => (-1213578601, [0, 0, 0, 1]),
            test_handshake_response_ok_2,
            test_handshake_response_partial_2
        ),
        (
            b"\x09\x00\x00\x00\x020\0" => (0, [0, 0, 0, 2]),
            test_handshake_response_ok_3,
            test_handshake_response_partial_3
        ),
        (
            b"\x09\x07\x06\x05\x40961876346\0" => (961876346, [7, 6, 5, 64]),
            test_handshake_response_ok_4,
            test_handshake_response_partial_4
        ),
    ];

    handshake_malformed_response_tests![
        (
            b"\x00\x07\x06\x05\x40961876346\0",
            test_handshake_response_malformed_invalid_type
        ),
        (
            b"\x09\x80\x00\x00\x009513307\0",
            test_handshake_response_malformed_invalid_id
        ),
        (
            b"\x09\x80",
            test_parse_handshake_response_malformed_partial_invalid_id
        ),
        (
            b"\x09\xc2\x80\xe0",
            test_parse_handshake_response_malformed_partial_overflowing_id
        ),
        (
            b"\x09\x00\x00\x00\x04\0",
            test_parse_handshake_response_malformed_terminator_without_payload
        ),
        (
            b"\x09\x00\x00\x00\x05@\x00",
            test_parse_handshake_response_malformed_invalid_payload_1
        ),
        (
            b"\x09\x00\x00\x00\x06-\x00",
            test_parse_handshake_response_malformed_invalid_payload_2
        ),
    ];

    basic_stat_request_tests![
        (
            ([0, 0, 1, 0], 9513307) =>
            [0xfe, 0xfd, 0x00, 0, 0, 1, 0, 0x00, 0x91, 0x29, 0x5bu8],
            test_basic_stat_request_1
        ),
        (
            ([0, 0, 2, 0], -1213578601) =>
            [0xfe, 0xfd, 0x00, 0, 0, 2, 0, 0xb7, 0xaa, 0x42, 0x97],
            test_basic_stat_request_2
        ),
        (
            ([0, 0, 3, 0], 0) =>
            [0xfe, 0xfd, 0x00, 0, 0, 3, 0, 0x00, 0x00, 0x00, 0x00],
            test_basic_stat_request_3
        ),
        (
            ([0, 0, 4, 0], 961876346) =>
            [0xfe, 0xfd, 0x00, 0, 0, 4, 0, 0x39, 0x55, 0x11, 0x7a],
            test_basic_stat_request_4
        ),
    ];

    basic_stat_response_tests![
        (
            b"\0\x00\x00\x01\x00A Minecraft Server\0SMP\0world\02\020\0\xdd\x63127.0.0.1\0" => (
                b"A Minecraft Server",
                b"SMP",
                b"world",
                2,
                20,
                25565,
                "127.0.0.1",
                [0, 0, 1, 0],
            ),
            test_basic_stat_response_ok_1,
            test_basic_stat_response_partial_1
        ),
        (
            b"\0\x00\x01\x00\x00\
              \xA7cA \xA76M\xA7ei\xA7an\xA79e\xA71c\xA75r\xA7ca\xA76f\xA7et \xA7aS\xA79e\xA71r\xA75v\xA7ce\
              \xA76r\xA7r\nNow colored and multiline\0\
              CMP\0middleearth\015\0200\0\xde\x630.0.0.0\0" => (
                b"\xA7cA \xA76M\xA7ei\xA7an\xA79e\xA71c\xA75r\xA7ca\xA76f\xA7et \xA7aS\xA79e\xA71r\xA75v\xA7ce\xA76r\
                \xA7r\nNow colored and multiline",
                b"CMP",
                b"middleearth",
                15,
                200,
                25566,
                "0.0.0.0",
                [0, 1, 0, 0],
            ),
            test_basic_stat_response_ok_2,
            test_basic_stat_response_partial_2
        )
    ];

    full_stat_response_tests![
        (
            b"\x00\x00\x00\x01\x00splitnum\x00\x80\x00hostname\0A Minecraft Server\0gametype\0SMP\0game_id\0MINECRAFT\0\
              version\0Beta 1.9 Prerelease 4\0plugins\0\0map\0world\0numplayers\02\0maxplayers\020\0hostport\025565\0\
              hostip\0127.0.0.1\0\0\x01player_\0\0barneygale\0Vivalahelvig\0\0" =>
            (
                b"A Minecraft Server",
                b"SMP",
                b"MINECRAFT",
                b"Beta 1.9 Prerelease 4",
                b"",
                b"world",
                2,
                20,
                25565,
                "127.0.0.1",
                [b"barneygale", b"Vivalahelvig"],
                [0, 0, 1, 0]
            ),
            test_full_stat_response_ok_1,
            test_full_stat_response_partial_1
        ),
        (
            b"\x00\x00\x01\x00\x00splitnum\x00\x80\x00\
              hostname\0\xA7cA \xA76M\xA7ei\xA7an\xA79e\xA71c\xA75r\xA7ca\xA76f\xA7et \xA7aS\xA79e\xA71r\xA75v\
              \xA7ce\xA76r\xA7r\nNow colored and multiline\0gametype\0CMP\0game_id\0MINECRAFT\0version\01.16.3\0\
              plugins\0CraftBukkit on Bukkit 1.2.5-R4.0: WorldEdit 5.3; CommandBook 2.1\0map\0middleearth\0\
              numplayers\010\0maxplayers\0200\0hostport\025566\0hostip\00.0.0.0\0\0\x01player_\0\0xXRingMaster2000Xx\
              \0GandalfTheGrey\0trolololo\0strider_\02Isengard\0NMYX\0Frodo\04theShire\0hob1937\0PRECIOUS\0\0" => (
                b"\xA7cA \xA76M\xA7ei\xA7an\xA79e\xA71c\xA75r\xA7ca\xA76f\xA7et \xA7aS\xA79e\xA71r\xA75v\
                  \xA7ce\xA76r\xA7r\nNow colored and multiline",
                b"CMP",
                b"MINECRAFT",
                b"1.16.3",
                b"CraftBukkit on Bukkit 1.2.5-R4.0: WorldEdit 5.3; CommandBook 2.1",
                b"middleearth",
                10,
                200,
                25566,
                "0.0.0.0",
                [
                    b"xXRingMaster2000Xx", b"GandalfTheGrey", b"trolololo", b"strider_", b"2Isengard",
                    b"NMYX", b"Frodo", b"4theShire", b"hob1937", b"PRECIOUS"
                ],
                [0, 1, 0, 0]
            ),
            test_full_stat_response_ok_2,
            test_full_stat_response_partial_2
        )
    ];
}
