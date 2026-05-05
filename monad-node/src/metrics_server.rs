// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::Arc;

use actix_server::Server;
use actix_web::{
    http::header::{self, HeaderValue},
    web, App, HttpRequest, HttpResponse, HttpServer,
};
use prometheus::{Encoder, ProtobufEncoder, Registry, TextEncoder};

#[derive(Clone)]
pub struct MetricsServerState {
    registry: Registry,
    before_gather: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl MetricsServerState {
    pub fn new(registry: Registry, before_gather: Option<Arc<dyn Fn() + Send + Sync>>) -> Self {
        Self {
            registry,
            before_gather,
        }
    }
}

fn wants_protobuf(request: &HttpRequest) -> bool {
    request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/vnd.google.protobuf"))
}

async fn handle_metrics(
    request: HttpRequest,
    state: web::Data<MetricsServerState>,
) -> HttpResponse {
    if let Some(before_gather) = &state.before_gather {
        before_gather();
    }

    let metric_families = state.registry.gather();
    let mut buffer = Vec::new();

    let content_type = if wants_protobuf(&request) {
        let encoder = ProtobufEncoder::new();
        if encoder.encode(&metric_families, &mut buffer).is_err() {
            return HttpResponse::InternalServerError().finish();
        }
        encoder.format_type().to_owned()
    } else {
        let encoder = TextEncoder::new();
        if encoder.encode(&metric_families, &mut buffer).is_err() {
            return HttpResponse::InternalServerError().finish();
        }
        encoder.format_type().to_owned()
    };

    HttpResponse::Ok()
        .insert_header((
            header::CONTENT_TYPE,
            HeaderValue::from_str(&content_type).unwrap_or_else(|_| {
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8")
            }),
        ))
        .body(buffer)
}

pub fn start_metrics_server(addr: String, state: MetricsServerState) -> std::io::Result<Server> {
    Ok(HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/metrics", web::get().to(handle_metrics))
    })
    .bind(addr)?
    .workers(1)
    .run())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use actix_web::{http::StatusCode, test, web, App};

    use super::{handle_metrics, MetricsServerState};

    #[actix_web::test]
    async fn metrics_route_calls_before_gather() {
        let counter = Arc::new(AtomicUsize::new(0));
        let before_gather = {
            let counter = Arc::clone(&counter);
            Arc::new(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            })
        };
        let state = MetricsServerState::new(prometheus::Registry::new(), Some(before_gather));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/metrics", web::get().to(handle_metrics)),
        )
        .await;

        let request = test::TestRequest::get().uri("/metrics").to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
