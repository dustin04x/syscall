use syscall_core::verify::{
    verify_exit_code, FindingSeverity, SessionVerificationReport, VerificationAssessment,
    VerificationFinding,
};

fn finding(severity: FindingSeverity, code: &str) -> VerificationFinding {
    VerificationFinding {
        code: code.to_owned(),
        severity,
        title: "t".to_owned(),
        detail: "d".to_owned(),
        session_id: Some("s".to_owned()),
        event_id: None,
        process_instance_id: None,
        evidence: vec![],
        recommendation: "r".to_owned(),
    }
}

#[test]
fn assessment_exit_codes_match_contract() {
    assert_eq!(verify_exit_code(VerificationAssessment::Valid), 0);
    assert_eq!(
        verify_exit_code(VerificationAssessment::ValidButIncomplete),
        2
    );
    assert_eq!(verify_exit_code(VerificationAssessment::Warning), 2);
    assert_eq!(verify_exit_code(VerificationAssessment::Invalid), 3);
    assert_eq!(verify_exit_code(VerificationAssessment::UnableToVerify), 4);
}

#[test]
fn compute_assessment_valid_when_no_warnings_or_errors() {
    let a = SessionVerificationReport::compute_assessment(&[], false);
    assert_eq!(a, VerificationAssessment::Valid);
    let a = SessionVerificationReport::compute_assessment(
        &[finding(
            FindingSeverity::Info,
            "PROVENANCE_UNAVAILABLE_LEGACY",
        )],
        false,
    );
    assert_eq!(a, VerificationAssessment::Valid);
}

#[test]
fn compute_assessment_incomplete_for_recovery_loss_or_unresolved() {
    for code in [
        "SESSION_RECOVERED",
        "SESSION_INCOMPLETE",
        "EVIDENCE_LOSS_RINGBUF",
        "EVIDENCE_LOSS_USERSPACE",
        "ACCOUNTING_INCOMPLETE",
        "PROVENANCE_UNAVAILABLE_LEGACY",
        "PROVENANCE_UNAVAILABLE",
        "FORK_IDENTITY_UNRESOLVED",
    ] {
        let a = SessionVerificationReport::compute_assessment(
            &[finding(FindingSeverity::Warning, code)],
            false,
        );
        assert_eq!(a, VerificationAssessment::ValidButIncomplete, "{code}");
    }
}

#[test]
fn compute_assessment_warning_without_completeness_limitations() {
    let a = SessionVerificationReport::compute_assessment(
        &[finding(FindingSeverity::Warning, "ACCOUNTING_INCONSISTENT")],
        false,
    );
    assert_eq!(a, VerificationAssessment::Warning);
}

#[test]
fn compute_assessment_invalid_on_error_or_critical() {
    let a = SessionVerificationReport::compute_assessment(
        &[finding(FindingSeverity::Error, "SESSION_STATUS_INVALID")],
        false,
    );
    assert_eq!(a, VerificationAssessment::Invalid);
    let a = SessionVerificationReport::compute_assessment(
        &[finding(
            FindingSeverity::Critical,
            "DB_INTEGRITY_CHECK_FAILED",
        )],
        false,
    );
    assert_eq!(a, VerificationAssessment::Invalid);
}

#[test]
fn compute_assessment_unable_when_required_checks_incomplete() {
    let a = SessionVerificationReport::compute_assessment(&[], true);
    assert_eq!(a, VerificationAssessment::UnableToVerify);
}
