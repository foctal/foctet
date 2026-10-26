use crate::database::{DriverError, QueryResult};
use serde_json::Value;
pub(crate) fn parse_pipeline(value: Value) -> Result<QueryResult, DriverError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or(DriverError::Failed)?;
    if results.len() != 2
        || results[0]["type"] != "ok"
        || results[0]["response"]["type"] != "execute"
        || results[1]["type"] != "ok"
        || results[1]["response"]["type"] != "close"
    {
        return Err(DriverError::Failed);
    }
    let result = &results[0]["response"]["result"];
    let count = result["affected_row_count"]
        .as_u64()
        .ok_or(DriverError::Failed)?;
    let columns = result["cols"].as_array().ok_or(DriverError::Failed)?;
    let rows = result["rows"].as_array().ok_or(DriverError::Failed)?;
    if columns.len() > 1 || rows.len() > 1 {
        return Err(DriverError::Failed);
    }
    let rows = rows
        .iter()
        .map(|row| {
            let row = row.as_array().ok_or(DriverError::Failed)?;
            if row.len() != columns.len() {
                return Err(DriverError::Failed);
            }
            row.iter()
                .map(|value| {
                    if value["type"] != "text" {
                        return Err(DriverError::Failed);
                    }
                    value["value"]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(DriverError::Failed)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(QueryResult {
        rows,
        affected_rows: count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn strict_pipeline_shape_and_values() {
        let valid = json!({"results":[{"type":"ok","response":{"type":"execute","result":{"cols":[{"name":"payload"}],"rows":[[{"type":"text","value":"opaque"}]],"affected_row_count":0}}},{"type":"ok","response":{"type":"close"}}]});
        assert_eq!(parse_pipeline(valid.clone()).unwrap().rows[0][0], "opaque");
        for invalid in [
            json!(null),
            json!([]),
            json!({"results":[]}),
            json!({"results":[{"type":"error"}]} ),
        ] {
            assert!(parse_pipeline(invalid).is_err());
        }
        for (field, bad) in [
            ("rows", json!([[{"type":"null"}]])),
            ("rows", json!([[], []])),
            ("cols", json!([])),
            ("affected_row_count", json!(-1)),
            ("affected_row_count", json!("1")),
        ] {
            let mut v = valid.clone();
            v["results"][0]["response"]["result"][field] = bad;
            assert!(parse_pipeline(v).is_err());
        }
        let mut v = valid;
        v["results"][1]["response"]["type"] = json!("execute");
        assert!(parse_pipeline(v).is_err());
    }
}
