#!/usr/bin/env bash

# Convert a json export from BigQuery to parseable JSON-lines of Login entries.
# The query:
#
# WITH base AS (
#   SELECT
#     submission_timestamp,
#     document_id,
#     event_offset,
#
#     MAX(IF(x.key = 'origin', x.value, NULL)) AS origin,
#     MAX(IF(x.key = 'form_action_origin', x.value, NULL)) AS form_action_origin,
#     MAX(IF(x.key = 'metric_version', x.value, NULL)) AS metric_version
#
#   FROM `moz-fx-data-shared-prod.firefox_desktop.pwmgr_origin_failure`,
#   UNNEST(events) AS e WITH OFFSET AS event_offset,
#   UNNEST(e.extra) AS x
#
#   WHERE DATE(submission_timestamp) >= '2026-03-23'
#
#   GROUP BY
#     submission_timestamp,
#     document_id,
#     event_offset
#   ORDER BY submission_timestamp DESC
# )
#
# SELECT origin, form_action_origin FROM base WHERE metric_version = "6" GROUP BY 1,2

# Nomalize origins:
# - https:// only
# - domain only
# - ftp mixups

jq -c '
  def normalize_origin:
    if test("^https:/{0,2}$") then
      "https://moz.pwmngr.fixed"

    # http://ftp.<IP>[:port] → ftp://<IP>
    elif test("^http://ftp\\.[0-9]+(\\.[0-9]+){3}(:[0-9]+)?$") then
    "ftp://" + (capture("^http://ftp\\.(?<ip>[0-9]+(\\.[0-9]+){3})").ip)

    # ftp.<IP> → ftp://<IP>
    elif test("^ftp\\.[0-9]+(\\.[0-9]+){3}$") then
      "ftp://" + (capture("^ftp\\.(?<ip>[0-9]+(\\.[0-9]+){3})$").ip)

    # ftp.<domain> → ftp://ftp.<domain>
    elif test("^ftp\\.[a-z0-9-]+(\\.[a-z0-9-]+)+$") then
      "ftp://" + .

    # bare domain → moz-pwmngr-fixed://domain
    elif test("^[a-z0-9-]+(\\.[a-z0-9-]+)+$") then
      "moz-pwmngr-fixed://" + .

    else
      .
    end;

  .[] |
  {
    origin: .origin,
    form_action_origin: .form_action_origin,
    password: "p",
    username: "u",
    username_field: "u",
    password_field: "p"
  } |
  .origin |= normalize_origin
'
