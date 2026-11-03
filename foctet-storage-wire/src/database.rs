//! Async execution for portable text records. Futures need not be Send, so
//! workers-rs bindings and request-scoped socket drivers can implement TextDriver.
use crate::{Dialect, Error, MAX_TEXT_BYTES, Statement, TextRecord, TextStore};

/// Opaque driver failure. Never include credentials, SQL or returned data.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// A duplicate primary key on INSERT. Other constraints are not conflicts.
    #[error("duplicate storage key")]
    DuplicateKey,
    /// Backend, network or malformed-response failure. Do not retry implicitly.
    #[error("storage driver failed")]
    Failed,
}
/// Text-only results from a single statement. Preserve all rows and columns so
/// the adapter can reject unexpected shape; do not silently take the first row.
#[derive(Debug)]
pub struct QueryResult {
    /// All result rows. Each value must be a non-null SQL text value.
    pub rows: Vec<Vec<String>>,
    /// Exact affected-row count, without floating-point rounding.
    pub affected_rows: u64,
}
/// Bridge to an existing database connection, including a driver on a
/// workers-rs Hyperdrive socket. Bind arguments as strings; never interpolate SQL.
/// The driver must bound network buffering, configure TLS/timeouts and use an
/// authoritative connection. No Send/Sync or thread-pool requirement is imposed.
#[allow(async_fn_in_trait)]
pub trait TextDriver {
    /// SQL dialect understood by this connection.
    fn dialect(&self) -> Dialect;
    /// Execute once. A timeout has an unknown write outcome, not a conflict.
    async fn execute(&mut self, statement: Statement) -> Result<QueryResult, DriverError>;
}
/// Portable validation or database failure, with no returned data in its display.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    /// Invalid record or revision.
    #[error(transparent)]
    Record(#[from] Error),
    /// Driver failure or duplicate key outside an insert operation.
    #[error(transparent)]
    Driver(#[from] DriverError),
}
/// Blind signed-TEXT persistence through a caller-owned async connection.
/// Parsing records is not writer verification. Call TextRecord::open at the
/// trusted endpoint with an independently known writer, identity and version.
pub struct AsyncTextStore<D> {
    driver: D,
    plans: TextStore,
    max_bytes: usize,
}
impl<D: TextDriver> AsyncTextStore<D> {
    /// Constructs a store without connecting or mutating schema.
    pub fn new(driver: D, max_bytes: usize) -> Result<Self, DatabaseError> {
        if max_bytes == 0 || max_bytes > MAX_TEXT_BYTES {
            return Err(Error::Invalid.into());
        }
        Ok(Self {
            plans: TextStore::new(driver.dialect()),
            driver,
            max_bytes,
        })
    }
    /// Returns the driver for connection lifecycle management by the application.
    pub fn into_driver(self) -> D {
        self.driver
    }
    /// Explicit migration; verifies MySQL/MariaDB tables use InnoDB even if an
    /// existing table was created under a nontransactional server default.
    pub async fn initialize(&mut self) -> Result<(), DatabaseError> {
        self.driver
            .execute(Statement {
                sql: self.plans.schema(),
                args: vec![],
            })
            .await?;
        if matches!(self.driver.dialect(), Dialect::Mysql) {
            let result = self.driver.execute(Statement {
                sql: "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'foctet_text_v1'",
                args: vec![],
            }).await?;
            if result.rows.len() != 1
                || result.rows[0].len() != 1
                || !result.rows[0][0].eq_ignore_ascii_case("InnoDB")
            {
                return Err(DriverError::Failed.into());
            }
        }
        Ok(())
    }
    /// Fetches one exact revision. Absence is not authenticated deletion; a
    /// returned value still requires pinned-writer verification at the endpoint.
    pub async fn get(
        &mut self,
        key: [u8; 32],
        expected: u64,
    ) -> Result<Option<TextRecord>, DatabaseError> {
        let result = self.driver.execute(self.plans.get(key, expected)?).await?;
        if result.rows.len() > 1 {
            return Err(DriverError::Failed.into());
        }
        match result.rows.into_iter().next() {
            None => Ok(None),
            Some(mut row) if row.len() == 1 => {
                Ok(Some(TextRecord::parse(&row.remove(0), self.max_bytes)?))
            }
            Some(_) => Err(DriverError::Failed.into()),
        }
    }
    /// Inserts revision 1 or advances exactly previous + 1. No automatic retry
    /// occurs. Reconcile ambiguous errors before updating a trusted checkpoint.
    pub async fn compare_and_swap(
        &mut self,
        key: [u8; 32],
        previous: Option<u64>,
        value: &TextRecord,
    ) -> Result<bool, DatabaseError> {
        if value.as_str().len() > self.max_bytes {
            return Err(Error::Invalid.into());
        }
        let statement = self.plans.compare_and_swap(key, previous, value)?;
        let result = match self.driver.execute(statement).await {
            Err(DriverError::DuplicateKey) if previous.is_none() => return Ok(false),
            other => other?,
        };
        if !result.rows.is_empty() {
            return Err(DriverError::Failed.into());
        }
        Ok(TextStore::write_succeeded(result.affected_rows)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};
    struct Driver {
        results: VecDeque<Result<QueryResult, DriverError>>,
        calls: Rc<RefCell<usize>>,
        mysql: bool,
    }
    impl TextDriver for Driver {
        fn dialect(&self) -> Dialect {
            if self.mysql {
                Dialect::Mysql
            } else {
                Dialect::Libsql
            }
        }
        async fn execute(&mut self, _statement: Statement) -> Result<QueryResult, DriverError> {
            *self.calls.borrow_mut() += 1;
            self.results.pop_front().expect("no unexpected retries")
        }
    }
    fn result(rows: Vec<Vec<String>>, affected_rows: u64) -> Result<QueryResult, DriverError> {
        Ok(QueryResult {
            rows,
            affected_rows,
        })
    }
    #[test]
    fn non_send_driver_validates_before_io_and_fails_closed() {
        futures::executor::block_on(async {
            let calls = Rc::new(RefCell::new(0));
            let text = TextRecord::from_parts(&[1], &[0; 64]).unwrap();
            let driver = Driver {
                calls: calls.clone(),
                mysql: false,
                results: VecDeque::from([
                    Err(DriverError::DuplicateKey),
                    Err(DriverError::DuplicateKey),
                    Err(DriverError::Failed),
                    result(vec![], 2),
                    result(vec![vec![], vec![]], 0),
                    result(vec![vec!["bad".into()]], 0),
                    result(vec![vec![text.as_str().into()]], 0),
                    result(vec![], 1),
                ]),
            };
            let mut store = AsyncTextStore::new(driver, 256).unwrap();
            assert!(store.get([0; 32], 0).await.is_err());
            assert!(
                store
                    .compare_and_swap([0; 32], Some(i64::MAX as u64), &text)
                    .await
                    .is_err()
            );
            assert_eq!(*calls.borrow(), 0);
            assert!(!store.compare_and_swap([0; 32], None, &text).await.unwrap());
            for _ in 0..3 {
                assert!(
                    store
                        .compare_and_swap([0; 32], Some(1), &text)
                        .await
                        .is_err()
                );
            }
            assert!(store.get([0; 32], 1).await.is_err());
            assert!(store.get([0; 32], 1).await.is_err());
            assert_eq!(
                store.get([0; 32], 1).await.unwrap().unwrap().as_str(),
                text.as_str()
            );
            assert!(
                store
                    .compare_and_swap([0; 32], Some(1), &text)
                    .await
                    .unwrap()
            );
            assert_eq!(*calls.borrow(), 8);
        });
    }
    #[test]
    fn rejects_nontransactional_mysql_schema_and_oversized_reads() {
        futures::executor::block_on(async {
            let driver = Driver {
                calls: Rc::new(RefCell::new(0)),
                mysql: true,
                results: VecDeque::from([
                    result(vec![], 0),
                    result(vec![vec!["MyISAM".into()]], 0),
                    result(vec![vec!["x".repeat(257)]], 0),
                ]),
            };
            let mut store = AsyncTextStore::new(driver, 256).unwrap();
            assert!(store.initialize().await.is_err());
            assert!(store.get([0; 32], 1).await.is_err());
        });
    }
}
