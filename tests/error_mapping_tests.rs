use axum::{http::StatusCode, response::IntoResponse};
use mandatepay::error::AppError;

// Covers error.rs mapping arms (From<rusqlite> + per-variant statuses).
#[test]
fn app_errors_map_to_expected_statuses() {
    let cases = [
        (AppError::BadRequest("x".into()), StatusCode::BAD_REQUEST),
        (AppError::Unauthorized("x".into()), StatusCode::UNAUTHORIZED),
        (AppError::NotFound("x".into()), StatusCode::NOT_FOUND),
        (
            AppError::Internal("x".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    for (err, status) in cases {
        assert_eq!(err.into_response().status(), status);
    }
}

#[test]
fn rusqlite_errors_become_internal() {
    let db_err = rusqlite::Connection::open(":memory:")
        .unwrap()
        .execute("THIS IS NOT SQL", [])
        .unwrap_err();
    let app_err = AppError::from(db_err);
    assert!(matches!(app_err, AppError::Internal(_)));
    assert_eq!(
        app_err.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
