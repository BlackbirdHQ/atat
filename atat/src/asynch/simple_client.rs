use super::AtatClient;
use crate::{helpers::LossyStr, AtatCmd, Config, DigestResult, Digester, Error, InternalError};
use embassy_time::{with_timeout, Duration, Timer};
use embedded_io_async::{Read, Write};

pub struct SimpleClient<'a, RW: Read + Write, D: Digester> {
    rw: RW,
    digester: D,
    buf: &'a mut [u8],
    pos: usize,
    config: Config,
    cooldown_timer: Option<Timer>,
}

impl<'a, RW: Read + Write, D: Digester> SimpleClient<'a, RW, D> {
    pub fn new(rw: RW, digester: D, buf: &'a mut [u8], config: Config) -> Self {
        Self {
            rw,
            digester,
            buf,
            config,
            pos: 0,
            cooldown_timer: None,
        }
    }

    /// Returns a mutable reference to the inner reader/writer.
    pub async fn inner(&mut self) -> &mut RW {
        self.wait_cooldown_timer().await;
        &mut self.rw
    }

    async fn send_request(&mut self, len: usize) -> Result<(), Error> {
        if len > 0 {
            if len < 50 {
                debug!("Sending command: {:?}", LossyStr(&self.buf[..len]));
            } else {
                debug!("Sending command with long payload ({} bytes)", len);
            }
            self.wait_cooldown_timer().await;

            // Write request
            with_timeout(self.config.tx_timeout, self.rw.write_all(&self.buf[..len]))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|_| Error::Write)?;
        }

        with_timeout(self.config.flush_timeout, self.rw.flush())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Write)?;

        self.start_cooldown_timer();
        Ok(())
    }

    async fn read_response_chunk(&mut self) -> Result<(), Error> {
        self.pos += self
            .rw
            .read(&mut self.buf[self.pos..])
            .await
            .or(Err(Error::Read))?;

        trace!(
            "Buffer contents: ({:?} bytes) '{:?}'",
            self.pos,
            LossyStr(&self.buf[..self.pos])
        );

        Ok(())
    }

    fn digest(&mut self) -> (Option<Result<&[u8], InternalError<'_>>>, usize) {
        let (result, swallowed) = self.digester.digest(&self.buf[..self.pos]);
        match &result {
            DigestResult::None if swallowed > 0 => debug!(
                "Received echo or whitespace ({}/{}): {:?}",
                swallowed,
                self.pos,
                LossyStr(&self.buf[..swallowed])
            ),
            DigestResult::None => {}
            DigestResult::Urc(urc_line) => {
                warn!("Unable to handle URC! Ignoring: {:?}", LossyStr(urc_line))
            }
            DigestResult::Prompt(_) => {
                debug!("Received prompt ({}/{})", swallowed, self.pos);
            }
            DigestResult::Response(Ok([])) => debug!("Received OK ({}/{})", swallowed, self.pos),
            DigestResult::Response(Ok(r)) => debug!(
                "Received response ({}/{}): {:?}",
                swallowed,
                self.pos,
                LossyStr(r)
            ),
            DigestResult::Response(Err(e)) => warn!(
                "Received error response ({}/{}): {:?}",
                swallowed, self.pos, e
            ),
        }
        let result = match result {
            DigestResult::Prompt(_) => Some(Ok(&[][..])),
            DigestResult::Response(resp) => Some(resp),
            _ => None,
        };
        (result, swallowed)
    }

    fn consume(&mut self, amt: usize) {
        self.buf.copy_within(amt..self.pos, 0);
        self.pos -= amt;
    }

    fn start_cooldown_timer(&mut self) {
        self.cooldown_timer = Some(Timer::after(self.config.cmd_cooldown));
    }

    async fn wait_cooldown_timer(&mut self) {
        if let Some(cooldown) = self.cooldown_timer.take() {
            cooldown.await
        }
    }
}

impl<RW: Read + Write, D: Digester> AtatClient for SimpleClient<'_, RW, D> {
    async fn send<Cmd: AtatCmd>(&mut self, cmd: &Cmd) -> Result<Cmd::Response, Error> {
        let len = cmd.write(self.buf);

        self.send_request(len).await?;
        if !Cmd::EXPECTS_RESPONSE_CODE {
            return cmd.parse(Ok(&[]));
        }

        self.pos = 0;

        let timeout = Duration::from_millis(Cmd::MAX_TIMEOUT_MS.into());
        embassy_time::with_timeout(timeout, async {
            loop {
                self.read_response_chunk().await?;
                while self.pos > 0 {
                    match self.digest() {
                        (Some(resp), _) => return cmd.parse(resp),
                        (_, 0) => break,
                        (_, swallowed) => self.consume(swallowed),
                    }
                }
                embassy_futures::yield_now().await;
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}
