package com.blueops.response;

public interface ResponseAdapter {
    String getAdapterType();
    boolean supports(ResponseProposalRecord proposal);
    ResponseExecutionResult dispatch(ResponseProposalRecord proposal);
}
