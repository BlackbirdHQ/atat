use heapless::{consts, ArrayLength, Vec};

use crate::error::Error;
use crate::queues::{ComConsumer, ResProducer, UrcItem, UrcProducer};
use crate::Command;
use crate::{
    atat_log,
    digest::{DefaultDigester, DigestResult, Digester},
    urc_matcher::{DefaultUrcMatcher, UrcMatcher},
};

pub struct IngressManager<
    BufLen = consts::U256,
    D = DefaultDigester,
    U = DefaultUrcMatcher,
    UrcCapacity = consts::U10,
> where
    BufLen: ArrayLength<u8>,
    UrcCapacity: ArrayLength<UrcItem<BufLen>>,
    U: UrcMatcher,
    D: Digester,
{
    /// Buffer holding incoming bytes.
    buf: Vec<u8, BufLen>,

    /// The response producer sends responses to the client
    res_p: ResProducer<BufLen>,
    /// The URC producer sends URCs to the client
    urc_p: UrcProducer<BufLen, UrcCapacity>,
    /// The command consumer receives commands from the client
    com_c: ComConsumer,

    /// Digester.
    digester: D,

    /// URC matcher.
    urc_matcher: U,
}

impl<BufLen, UrcCapacity> IngressManager<BufLen, DefaultDigester, DefaultUrcMatcher, UrcCapacity>
where
    BufLen: ArrayLength<u8>,
    UrcCapacity: ArrayLength<UrcItem<BufLen>>,
{
    #[must_use]
    pub fn new(
        res_p: ResProducer<BufLen>,
        urc_p: UrcProducer<BufLen, UrcCapacity>,
        com_c: ComConsumer,
    ) -> Self {
        Self::with_customs(
            res_p,
            urc_p,
            com_c,
            DefaultUrcMatcher::default(),
            DefaultDigester::default(),
        )
    }
}

impl<BufLen, U, D, UrcCapacity> IngressManager<BufLen, D, U, UrcCapacity>
where
    D: Digester,
    U: UrcMatcher,
    BufLen: ArrayLength<u8>,
    UrcCapacity: ArrayLength<UrcItem<BufLen>>,
{
    pub fn with_customs(
        res_p: ResProducer<BufLen>,
        urc_p: UrcProducer<BufLen, UrcCapacity>,
        com_c: ComConsumer,
        urc_matcher: U,
        digester: D,
    ) -> Self {
        Self {
            buf: Vec::new(),
            res_p,
            urc_p,
            com_c,
            urc_matcher,
            digester,
        }
    }

    /// Write data into the internal buffer raw bytes being the core type allows
    /// the ingress manager to be abstracted over the communication medium.
    ///
    /// This function should be called by the UART Rx, either in a receive
    /// interrupt, or a DMA interrupt, to move data from the peripheral into the
    /// ingress manager receive buffer.
    pub fn write(&mut self, data: &[u8]) {
        atat_log!(trace, "Write: \"{:?}\"", data);

        if self.buf.extend_from_slice(data).is_err() {
            atat_log!(
                error,
                "OVERFLOW DATA! Buffer: {:?}",
                core::convert::AsRef::<[u8]>::as_ref(&self.buf)
            );
            self.notify_response(Err(Error::Overflow));
        }
    }

    /// Notify the client that an appropriate response code, or error has been
    /// received
    pub fn notify_response(&mut self, resp: Result<Vec<u8, BufLen>, Error>) {
        match &resp {
            Ok(_r) => {
                if _r.is_empty() {
                    atat_log!(debug, "Received OK")
                } else {
                    #[allow(clippy::single_match)]
                    match core::str::from_utf8(_r) {
                        Ok(_s) => {
                            #[cfg(not(feature = "log-logging"))]
                            atat_log!(debug, "Received response: \"{:str}\"", _s);
                            #[cfg(feature = "log-logging")]
                            atat_log!(debug, "Received response \"{:?}\"", _s)
                        }
                        Err(_) => atat_log!(
                            debug,
                            "Received response: {:?}",
                            core::convert::AsRef::<[u8]>::as_ref(&_r)
                        ),
                    };
                }
            }
            Err(_e) => atat_log!(error, "Received error response: {:?}", _e),
        }
        if self.res_p.ready() {
            unsafe { self.res_p.enqueue_unchecked(resp) };
        } else {
            // FIXME: Handle queue not being ready
            atat_log!(error, "Response queue full!");
        }
    }

    /// Notify the client that an unsolicited response code (URC) has been
    /// received
    pub fn notify_urc(&mut self, resp: Vec<u8, BufLen>) {
        #[allow(clippy::single_match)]
        match core::str::from_utf8(&resp) {
            Ok(_s) => {
                #[cfg(not(feature = "log-logging"))]
                atat_log!(debug, "Received URC: {:str}", _s);
                #[cfg(feature = "log-logging")]
                atat_log!(debug, "Received URC: {:?}", _s);
            }
            Err(_) => atat_log!(
                debug,
                "Received URC: {:?}",
                core::convert::AsRef::<[u8]>::as_ref(&resp)
            ),
        };

        if self.urc_p.ready() {
            unsafe { self.urc_p.enqueue_unchecked(resp) };
        } else {
            // FIXME: Handle queue not being ready
            atat_log!(error, "URC queue full!");
        }
    }

    /// Handle receiving internal config commands from the client.
    pub fn handle_com(&mut self) {
        if let Some(com) = self.com_c.dequeue() {
            match com {
                Command::Reset => {
                    self.digester.reset();
                    self.buf.clear();
                    atat_log!(trace, "Cleared complete buffer");
                }
                Command::ForceReceiveState => self.digester.force_receive_state(),
            }
        }
    }

    pub fn digest(&mut self) {
        loop {
            // Handle commands every loop to catch timeouts asap
            self.handle_com();

            match self.digester.digest(&mut self.buf, &mut self.urc_matcher) {
                DigestResult::None => return,
                DigestResult::Urc(urc_line) => self.notify_urc(urc_line),
                DigestResult::Response(resp) => self.notify_response(resp),
            };
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::queues::{ComQueue, ResQueue, UrcQueue};
    use heapless::{consts, spsc::Queue};

    type TestRxBufLen = consts::U256;
    type TestUrcCapacity = consts::U10;

    #[test]
    fn overflow() {
        static mut RES_Q: ResQueue<TestRxBufLen> = Queue(heapless::i::Queue::u8());
        let (res_p, mut res_c) = unsafe { RES_Q.split() };
        static mut URC_Q: UrcQueue<TestRxBufLen, TestUrcCapacity> = Queue(heapless::i::Queue::u8());
        let (urc_p, _urc_c) = unsafe { URC_Q.split() };
        static mut COM_Q: ComQueue = Queue(heapless::i::Queue::u8());
        let (_com_p, com_c) = unsafe { COM_Q.split() };

        let mut ingress = IngressManager::with_customs(
            res_p,
            urc_p,
            com_c,
            DefaultUrcMatcher::default(),
            DefaultDigester::default(),
        );

        ingress.write(b"+USORD: 3,266,\"");
        for _ in 0..266 {
            ingress.write(b"s");
        }
        ingress.write(b"\"\r\n");
        ingress.digest();
        assert_eq!(res_c.dequeue().unwrap(), Err(Error::Overflow));
    }
}
