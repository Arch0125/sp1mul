use rusqlite::{ffi::SQLITE_DETERMINISTIC, functions::FunctionFlags, params, Connection, Result};

fn main() -> Result<()> {
    // Open a connection to a local SQLite database file.
    // This file will be created if it does not exist.
    let conn = Connection::open("example.db")?;

    // Create a table if it doesn't already exist.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS my_table (
            id    INTEGER PRIMARY KEY,
            value REAL NOT NULL
        )",
        [],
    )?;

    // Insert sample data into the table.
    // For simplicity, we insert three rows. In production you might
    // check for duplicates or use transactions.
    conn.execute("INSERT INTO my_table (value) VALUES (?1)", params![10.0])?;
    conn.execute("INSERT INTO my_table (value) VALUES (?1)", params![20.0])?;
    conn.execute("INSERT INTO my_table (value) VALUES (?1)", params![30.0])?;

    // Register the custom scalar function FHEADD.
    // The function accepts two arguments and returns their sum.
    conn.create_scalar_function(
        "FHEADD",
        2,           // number of arguments
        FunctionFlags::SQLITE_DETERMINISTIC,        // deterministic (the same inputs yield the same output)
        |ctx| {
            // Retrieve the two f64 arguments.
            let a = ctx.get::<f64>(0)?;
            let b = ctx.get::<f64>(1)?;
            Ok(a + b)
        },
    )?;

    // Run a query that uses both standard SQL and the custom FHEADD function.
    let mut stmt = conn.prepare(
        "SELECT id, value, FHEADD(value, 2.0) as new_value FROM my_table"
    )?;

    let rows = stmt.query_map([], |row| {
        let id: i64 = row.get(0)?;
        let value: f64 = row.get(1)?;
        let new_value: f64 = row.get(2)?;
        Ok((id, value, new_value))
    })?;

    println!("--- Query Results ---");
    for row in rows {
        let (id, value, new_value) = row?;
        println!("id: {}, value: {}, new_value: {}", id, value, new_value);
    }

    // Run a standard SQL query to verify that existing functionalities work as expected.
    let mut stmt2 = conn.prepare("SELECT 1.0 + 2.0 as sum")?;
    let sum: f64 = stmt2.query_row([], |row| row.get(0))?;
    println!("Standard SQL Query Result: 1.0 + 2.0 = {}", sum);

    Ok(())
}
