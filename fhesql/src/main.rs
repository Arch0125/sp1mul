use rusqlite::{functions::FunctionFlags, params, Connection, Result};
use paillier_rs::keygen::paillier_keygen;
use paillier_rs::encrypt::paillier_encrypt;
use paillier_rs::decrypt::paillier_decrypt;
use paillier_rs::arithmetic::paillier_add;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, One};

fn main() -> Result<()> {
    // Open (or create) the local SQLite database.
    let conn = Connection::open("example.db")?;

    // Generate Paillier keys (using 64-bit primes for demonstration).
    let bits = 256;
    let (pubkey, privkey) = paillier_keygen(bits);

    // Create a table to store encrypted values.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS encrypted_table (
            id         INTEGER PRIMARY KEY,
            ciphertext TEXT NOT NULL
        )",
        [],
    )?;

    // Insert sample plaintext values (encrypt them first).
    let plaintexts = vec![10u32, 20u32, 30u32];
    for &m in &plaintexts {
        let m_big = BigUint::from(m);
        let c = paillier_encrypt(&pubkey, &m_big);
        let c_str = c.to_str_radix(10);
        conn.execute("INSERT INTO encrypted_table (ciphertext) VALUES (?1)", params![c_str])?;
    }

    // Register the custom scalar function FHEADD.
    // FHEADD takes two ciphertext strings (base‑10), parses them into BigUint,
    // adds them homomorphically using paillier_add, and returns the resulting ciphertext as a string.
    let pubkey_clone = pubkey.clone(); // clone public key for use in the closure.
    conn.create_scalar_function(
        "FHEADD",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let s1: String = ctx.get(0)?;
            let s2: String = ctx.get(1)?;
            let c1 = BigUint::parse_bytes(s1.as_bytes(), 10)
                .ok_or_else(|| rusqlite::Error::UserFunctionError("Failed to parse ciphertext 1".into()))?;
            let c2 = BigUint::parse_bytes(s2.as_bytes(), 10)
                .ok_or_else(|| rusqlite::Error::UserFunctionError("Failed to parse ciphertext 2".into()))?;
            let c_sum = paillier_add(&c1, &c2, &pubkey_clone);
            Ok(c_sum.to_str_radix(10))
        },
    )?;

    // Query the table to get id, original ciphertext, and doubled ciphertext (via FHEADD).
    let mut stmt = conn.prepare(
        "SELECT id, ciphertext, FHEADD(ciphertext, ciphertext) as doubled 
         FROM encrypted_table"
    )?;
    let rows = stmt.query_map([], |row| {
        let id: i64 = row.get(0)?;
        let orig: String = row.get(1)?;
        let doubled: String = row.get(2)?;
        Ok((id, orig, doubled))
    })?;

    // Collect results with decryption of both original and doubled ciphertexts.
    let mut results = Vec::new();
    for row in rows {
        let (id, orig, doubled) = row?;
        // Parse and decrypt original ciphertext.
        let orig_big = BigUint::parse_bytes(orig.as_bytes(), 10)
            .ok_or(rusqlite::Error::UserFunctionError("Failed to parse original ciphertext".into()))?;
        let dec_orig = paillier_decrypt(&privkey, &pubkey, &orig_big);
        // Parse and decrypt doubled ciphertext.
        let doubled_big = BigUint::parse_bytes(doubled.as_bytes(), 10)
            .ok_or(rusqlite::Error::UserFunctionError("Failed to parse doubled ciphertext".into()))?;
        let dec_doubled = paillier_decrypt(&privkey, &pubkey, &doubled_big);
        results.push((id, orig, dec_orig, doubled, dec_doubled));
    }

    // Define fixed column widths.
    let id_w = 4;
    let ct_w = 44; // original ciphertext column width
    let d_orig_w = 20; // decrypted original
    let dbl_w = 44; // doubled ciphertext
    let d_dbl_w = 20; // decrypted doubled

    // Print header.
    println!(
        "+{:-<id$}+{:-<ct$}+{:-<d_orig$}+{:-<dbl$}+{:-<d_dbl$}+",
        "", "", "", "", "",
        id = id_w + 2,
        ct = ct_w + 2,
        d_orig = d_orig_w + 2,
        dbl = dbl_w + 2,
        d_dbl = d_dbl_w + 2,
    );
    println!(
        "| {:^id$} | {:^ct$} | {:^d_orig$} | {:^dbl$} | {:^d_dbl$} |",
        "id", "Original Ciphertext", "Decrypted Orig", "Doubled Ciphertext", "Decrypted Doubled",
        id = id_w,
        ct = ct_w,
        d_orig = d_orig_w,
        dbl = dbl_w,
        d_dbl = d_dbl_w,
    );
    println!(
        "+{:-<id$}+{:-<ct$}+{:-<d_orig$}+{:-<dbl$}+{:-<d_dbl$}+",
        "", "", "", "", "",
        id = id_w + 2,
        ct = ct_w + 2,
        d_orig = d_orig_w + 2,
        dbl = dbl_w + 2,
        d_dbl = d_dbl_w + 2,
    );

    // Print each row.
    for (id, orig, dec_orig, doubled, dec_doubled) in results {
        let dec_orig_str = dec_orig.to_u32().map(|n| n.to_string())
            .unwrap_or_else(|| dec_orig.to_str_radix(10));
        let dec_doubled_str = dec_doubled.to_u32().map(|n| n.to_string())
            .unwrap_or_else(|| dec_doubled.to_str_radix(10));
        println!(
            "| {:<id$} | {:<ct$} | {:<d_orig$} | {:<dbl$} | {:<d_dbl$} |",
            id,
            orig,
            dec_orig_str,
            doubled,
            dec_doubled_str,
            id = id_w,
            ct = ct_w,
            d_orig = d_orig_w,
            dbl = dbl_w,
            d_dbl = d_dbl_w,
        );
    }
    println!(
        "+{:-<id$}+{:-<ct$}+{:-<d_orig$}+{:-<dbl$}+{:-<d_dbl$}+",
        "", "", "", "", "",
        id = id_w + 2,
        ct = ct_w + 2,
        d_orig = d_orig_w + 2,
        dbl = dbl_w + 2,
        d_dbl = d_dbl_w + 2,
    );

    Ok(())
}
