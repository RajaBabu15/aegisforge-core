import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: 50,
  duration: "2m",
  thresholds: {
    http_req_duration: ["p(95)<45"],
  },
};

const base = __ENV.BASE_URL || "http://localhost:8000";
const token = __ENV.ACCESS_TOKEN;

export default function () {
  const response = http.get(`${base}/api/v1/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  check(response, {
    "cached authorization": (res) => res.status === 200,
  });
}
