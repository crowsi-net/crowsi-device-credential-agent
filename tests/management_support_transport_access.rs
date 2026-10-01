impl FakeTransport {
    pub fn respond(&self, wire: Vec<u8>) {
        *self.response.lock().expect("response") = wire;
    }
    pub fn respond_lookup(&self, wire: Vec<u8>) {
        *self.lookup_response.lock().expect("lookup response") = wire;
    }
    pub fn respond_finalize(&self, wire: Vec<u8>) {
        *self.finalize_response.lock().expect("finalize response") = wire;
    }
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("requests").clone()
    }
    pub fn finalize_requests(&self) -> Vec<Vec<u8>> {
        self.finalize_requests
            .lock()
            .expect("finalize requests")
            .clone()
    }
    pub fn source_approve_requests(&self) -> Vec<Vec<u8>> {
        self.source_approve_requests
            .lock()
            .expect("source approve requests")
            .clone()
    }
    pub fn reservation_requests(&self) -> Vec<Vec<u8>> {
        self.reservation_requests
            .lock()
            .expect("reservation requests")
            .clone()
    }
    pub fn fail_finalize_once(&self) {
        *self.fail_finalize_once.lock().expect("finalize failure") = true;
    }
    pub fn fail_source_approve_once(&self) {
        *self
            .fail_source_approve_once
            .lock()
            .expect("source approve failure") = true;
    }
}
