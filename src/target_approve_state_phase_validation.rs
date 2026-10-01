use crate::target_approve_state_types::{TargetApprovePhaseV1, TargetApproveRecordV1};

pub(super) fn valid(value: &TargetApproveRecordV1) -> bool {
    let finish = value.finish_exchange.is_some();
    let current_request = value.current_request.is_some();
    let current = value.current_exchange.is_some();
    let observed = value.current_observed_at_epoch_s.is_some();
    let pa_request = value.pa_request.is_some();
    let pa_response = value.pa_response.is_some();
    let custody = value.custody_response.is_some();
    let central = value.target_proof.is_some();
    let response = value.response.is_some();
    let paired = same(&value.pa_request_json, &value.pa_request)
        && same(&value.pa_response_json, &value.pa_response)
        && same(&value.custody_response_json, &value.custody_response)
        && same(&value.central_envelope_json, &value.central_envelope)
        && value.central_envelope.is_some() == central
        && same(&value.response_json, &value.response);
    if !paired {
        return false;
    }
    match value.phase {
        TargetApprovePhaseV1::FinishPrepared
        | TargetApprovePhaseV1::FinishInvoking
        | TargetApprovePhaseV1::FinishUnknown => none(&[
            finish,
            current_request,
            current,
            observed,
            pa_request,
            pa_response,
            custody,
            central,
            response,
        ]),
        TargetApprovePhaseV1::CurrentRequestPrepared => {
            finish
                && none(&[
                    current_request,
                    current,
                    observed,
                    pa_request,
                    pa_response,
                    custody,
                    central,
                    response,
                ])
        }
        TargetApprovePhaseV1::CurrentPrepared
        | TargetApprovePhaseV1::CurrentInvoking
        | TargetApprovePhaseV1::CurrentUnknown => {
            finish
                && current_request
                && none(&[
                    current,
                    observed,
                    pa_request,
                    pa_response,
                    custody,
                    central,
                    response,
                ])
        }
        TargetApprovePhaseV1::CurrentObservePrepared
        | TargetApprovePhaseV1::CurrentObserveInvoking
        | TargetApprovePhaseV1::CurrentObserveUnknown => {
            finish
                && current_request
                && current
                && observed
                && none(&[pa_request, pa_response, custody, central, response])
        }
        TargetApprovePhaseV1::PaPrepared
        | TargetApprovePhaseV1::PaInvoking
        | TargetApprovePhaseV1::PaUnknown => {
            finish
                && current_request
                && current
                && observed
                && pa_request
                && none(&[pa_response, custody, central, response])
        }
        TargetApprovePhaseV1::CustodyPrepared
        | TargetApprovePhaseV1::CustodyInvoking
        | TargetApprovePhaseV1::CustodyUnknown => {
            finish
                && current_request
                && current
                && observed
                && pa_request
                && pa_response
                && none(&[custody, central, response])
        }
        TargetApprovePhaseV1::CentralPrepared
        | TargetApprovePhaseV1::CentralInvoking
        | TargetApprovePhaseV1::Unknown => {
            finish
                && current_request
                && current
                && observed
                && pa_request
                && pa_response
                && custody
                && central
                && !response
        }
        TargetApprovePhaseV1::Complete => {
            finish
                && current_request
                && current
                && observed
                && pa_request
                && pa_response
                && custody
                && central
                && response
        }
    }
}

fn same<T, U>(left: &Option<T>, right: &Option<U>) -> bool {
    left.is_some() == right.is_some()
}

fn none(values: &[bool]) -> bool {
    values.iter().all(|value| !value)
}
