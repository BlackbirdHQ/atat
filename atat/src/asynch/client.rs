use super::AtatClient;
use crate::{
    helpers::LossyStr,
    response_slot::{ResponseSlot, ResponseSlotGuard},
    AtatCmd, Config, Error,
};
use embassy_time::{with_timeout, Duration, Instant, TimeoutError, Timer};
use embedded_io::ErrorType;
use embedded_io_async::Write;
use futures::{
    future::{select, Either},
    pin_mut, Future,
};

pub struct Client<'a, W: Write, const INGRESS_BUF_SIZE: usize> {
    writer: W,
    res_slot: &'a ResponseSlot<INGRESS_BUF_SIZE>,
    buf: &'a mut [u8],
    config: Config,
    cooldown_timer: Option<Timer>,
}

impl<'a, W: Write, const INGRESS_BUF_SIZE: usize> Client<'a, W, INGRESS_BUF_SIZE> {
    pub fn new(
        writer: W,
        res_slot: &'a ResponseSlot<INGRESS_BUF_SIZE>,
        buf: &'a mut [u8],
        config: Config,
    ) -> Self {
        Self {
            writer,
            res_slot,
            buf,
            config,
            cooldown_timer: None,
        }
    }

    /// Returns a mutable reference to the inner writer.
    pub async fn inner(&mut self) -> &mut W {
        self.res_slot.reset();
        self.wait_cooldown_timer().await;
        &mut self.writer
    }
}

impl<W: Write, const INGRESS_BUF_SIZE: usize> ErrorType for Client<'_, W, INGRESS_BUF_SIZE> {
    type Error = Error;
}

impl<'a, W: Write, const INGRESS_BUF_SIZE: usize> Client<'a, W, INGRESS_BUF_SIZE> {
    async fn send_request(&mut self, len: usize) -> Result<(), Error> {
        if len > 0 {
            if len < 50 {
                debug!("Sending command: {:?}", LossyStr(&self.buf[..len]));
            } else {
                debug!("Sending command with long payload ({} bytes)", len);
            }

            self.wait_cooldown_timer().await;

            // Clear any pending response signal
            self.res_slot.reset();

            // Write request
            with_timeout(
                self.config.tx_timeout,
                self.writer.write_all(&self.buf[..len]),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Write)?;
        }

        with_timeout(self.config.flush_timeout, self.writer.flush())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Write)?;

        self.start_cooldown_timer();
        Ok(())
    }

    async fn wait_response<'guard>(
        &'guard mut self,
        timeout: Duration,
    ) -> Result<ResponseSlotGuard<'guard, INGRESS_BUF_SIZE>, Error> {
        self.with_timeout(timeout, self.res_slot.get())
            .await
            .map_err(|_| Error::Timeout)
    }

    async fn with_timeout<F: Future>(
        &self,
        timeout: Duration,
        fut: F,
    ) -> Result<F::Output, TimeoutError> {
        let start = Instant::now();
        let mut expires = (self.config.get_response_timeout)(start, timeout);

        pin_mut!(fut);

        loop {
            fut = match select(fut, Timer::at(expires)).await {
                Either::Left((r, _)) => return Ok(r),
                Either::Right((_, fut)) => {
                    let new_expires = (self.config.get_response_timeout)(start, timeout);
                    if new_expires <= expires {
                        return Err(TimeoutError);
                    }
                    expires = new_expires;
                    fut
                }
            };
        }
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

impl<W: Write, const INGRESS_BUF_SIZE: usize> AtatClient for Client<'_, W, INGRESS_BUF_SIZE> {
    async fn send<Cmd: AtatCmd>(&mut self, cmd: &Cmd) -> Result<Cmd::Response, Error> {
        let len = cmd.write(self.buf);
        self.send_request(len).await?;
        if !Cmd::EXPECTS_RESPONSE_CODE {
            cmd.parse(Ok(&[]))
        } else {
            let response = self
                .wait_response(Duration::from_millis(Cmd::MAX_TIMEOUT_MS.into()))
                .await?;
            cmd.parse((&*response).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate as atat;
    use crate::atat_derive::{AtatCmd, AtatEnum, AtatResp};
    use crate::Error;
    use core::sync::atomic::{AtomicU64, Ordering};
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::pubsub::PubSubChannel;
    use embassy_time::{Duration, Instant, Timer};
    use heapless::String;
    use tokio::join;

    const TEST_RX_BUF_LEN: usize = 256;

    #[derive(Clone, AtatCmd)]
    #[at_cmd("+CFUN", NoResponse, timeout_ms = 180000)]
    pub struct SetModuleFunctionality {
        #[at_arg(position = 0)]
        pub fun: Functionality,
        #[at_arg(position = 1)]
        pub rst: Option<ResetMode>,
    }

    #[derive(Clone, PartialEq, AtatEnum)]
    #[at_enum(u8)]
    #[allow(clippy::upper_case_acronyms)]
    pub enum Functionality {
        #[at_arg(value = 0)]
        Min,
        #[at_arg(value = 1)]
        Full,
        #[at_arg(value = 4)]
        APM,
        #[at_arg(value = 6)]
        DM,
    }

    #[derive(Clone, PartialEq, AtatEnum)]
    #[at_enum(u8)]
    pub enum ResetMode {
        #[at_arg(value = 0)]
        DontReset,
        #[at_arg(value = 1)]
        Reset,
    }

    #[derive(Clone, AtatResp, PartialEq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct NoResponse;

    macro_rules! setup {
        ($config:expr) => {{
            static TX_CHANNEL: PubSubChannel<CriticalSectionRawMutex, String<64>, 1, 1, 1> =
                PubSubChannel::new();
            static RES_SLOT: ResponseSlot<TEST_RX_BUF_LEN> = ResponseSlot::new();
            static mut BUF: [u8; 1000] = [0; 1000];

            let tx_mock = crate::tx_mock::TxMock::new(TX_CHANNEL.publisher().unwrap());
            let client: Client<crate::tx_mock::TxMock, TEST_RX_BUF_LEN> = Client::new(
                tx_mock,
                &RES_SLOT,
                unsafe { &mut *core::ptr::addr_of_mut!(BUF) },
                $config,
            );
            (client, TX_CHANNEL.subscriber().unwrap(), &RES_SLOT)
        }};
    }

    #[tokio::test]
    async fn custom_timeout() {
        static CALL_COUNT: AtomicU64 = AtomicU64::new(0);

        fn custom_response_timeout(sent: Instant, timeout: Duration) -> Instant {
            CALL_COUNT.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                Duration::from_millis(SetModuleFunctionality::MAX_TIMEOUT_MS.into()),
                timeout
            );
            // Effectively ignoring the timeout configured for the command
            // The default response timeout is "sent + timeout"
            sent + Duration::from_millis(100)
        }

        let (mut client, mut tx, _slot) =
            setup!(Config::new().get_response_timeout(custom_response_timeout));

        let cmd = SetModuleFunctionality {
            fun: Functionality::APM,
            rst: Some(ResetMode::DontReset),
        };

        let sent = tokio::spawn(async move {
            tx.next_message_pure().await;
            // Do not emit a response effectively causing a timeout
        });

        let send = tokio::spawn(async move {
            assert_eq!(Err(Error::Timeout), client.send(&cmd).await);
        });

        let (sent, send) = join!(sent, send);
        sent.unwrap();
        send.unwrap();

        assert_ne!(0, CALL_COUNT.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn custom_timeout_modified_during_request() {
        static CALL_COUNT: AtomicU64 = AtomicU64::new(0);

        fn custom_response_timeout(sent: Instant, timeout: Duration) -> Instant {
            CALL_COUNT.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                Duration::from_millis(SetModuleFunctionality::MAX_TIMEOUT_MS.into()),
                timeout
            );
            // Effectively ignoring the timeout configured for the command
            // The default response timeout is "sent + timeout"
            // Let the timeout instant be extended depending on the current time
            if Instant::now() < sent + Duration::from_millis(100) {
                // Initial timeout
                sent + Duration::from_millis(200)
            } else {
                // Extended timeout
                sent + Duration::from_millis(50000)
            }
        }

        let (mut client, mut tx, slot) =
            setup!(Config::new().get_response_timeout(custom_response_timeout));

        let cmd = SetModuleFunctionality {
            fun: Functionality::APM,
            rst: Some(ResetMode::DontReset),
        };

        let sent = tokio::spawn(async move {
            tx.next_message_pure().await;
            // Emit response in the extended timeout timeframe
            Timer::after(Duration::from_millis(300)).await;
            slot.signal_response(Ok(&[])).unwrap();
        });

        let send = tokio::spawn(async move {
            assert_eq!(Ok(NoResponse), client.send(&cmd).await);
        });

        let (sent, send) = join!(sent, send);
        sent.unwrap();
        send.unwrap();

        assert_ne!(0, CALL_COUNT.load(Ordering::Relaxed));
    }
}
