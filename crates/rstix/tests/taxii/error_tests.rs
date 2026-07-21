use rstix::taxii::TaxiiError;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use super::support::{taxii_json, wiremock_client};

macro_rules! maps_status {
    ($name:ident, $status:expr, $variant:pat) => {
        #[tokio::test]
        async fn $name() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/taxii2/"))
                .respond_with(taxii_json(
                    $status,
                    serde_json::json!({
                        "title": "error",
                        "description": "detail message"
                    }),
                ))
                .mount(&server)
                .await;

            let client = wiremock_client(&server);
            let err = client.discover().await.expect_err("error");
            assert!(matches!(err, $variant));
        }
    };
}

maps_status!(maps_400, 400, TaxiiError::BadRequest { .. });
maps_status!(maps_401, 401, TaxiiError::Unauthorized { .. });
maps_status!(maps_403, 403, TaxiiError::Forbidden { .. });
maps_status!(maps_404, 404, TaxiiError::NotFound { .. });
maps_status!(maps_406, 406, TaxiiError::NotAcceptable { .. });
maps_status!(maps_413, 413, TaxiiError::PayloadTooLarge { .. });
maps_status!(
    maps_416,
    416,
    TaxiiError::RequestedRangeNotSatisfiable { .. }
);
maps_status!(maps_422, 422, TaxiiError::UnprocessableEntity { .. });
maps_status!(maps_429, 429, TaxiiError::RateLimited { .. });
maps_status!(maps_415, 415, TaxiiError::UnsupportedMediaType { .. });
maps_status!(maps_503, 503, TaxiiError::ServerError { status: 503, .. });
