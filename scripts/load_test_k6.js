import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: 10,
  duration: "30s",
  thresholds: {
    http_req_duration: ["p(95)<800"],
    checks: ["rate>0.99"],
  },
};

const base = __ENV.BASE_URL || "http://localhost:8000";
const token = __ENV.ACCESS_TOKEN;

export default function () {
  const response = http.get(`${base}/api/v1/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  check(response, {
    "me 200": (res) => res.status === 200,
  });
}
