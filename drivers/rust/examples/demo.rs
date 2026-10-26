// SPDX-License-Identifier: Apache-2.0
// Start a keyless server first (pip install ./parser ./core ./drivers/python ./server, see
// docs/GETTING_STARTED.md):
//   torusdb-server --port 8533
// then, in drivers/rust:  cargo run --example demo
// (creates table `emp`; start a fresh server to run it again)
use num_bigint::BigInt;
use torusdb::{all, eq_int, CellIn, Client, Column, ConnectOptions, JoinOptions, JoinStep};

fn col(name: &str, ty: &str, policy: &str) -> Column {
    Column { name: name.into(), ty: ty.into(), policy: policy.into() }
}

fn main() -> Result<(), String> {
    // For a protected server: Client::connect_with(addr, &ConnectOptions {
    //     token: Some(std::env::var("TORUSDB_TOKEN").unwrap()), tls: true, ..Default::default() })
    let mut db = Client::connect_with("127.0.0.1:8533", &ConnectOptions::default())?;

    db.create_table(
        "emp",
        vec![
            col("id", "int", "plain"),
            col("dept", "int", "plain"),
            col("salary", "rational", "encrypted"),
            col("rate", "int", "paired"),
            col("hours", "int", "paired"),
        ],
    )?;

    let rows: Vec<Vec<(&str, CellIn)>> = [(1, 5, 8000, 50, 40), (2, 5, 9000, 60, 35), (3, 9, 7000, 45, 40)]
        .into_iter()
        .map(|(id, dept, sal, rate, hours)| {
            vec![
                ("id", CellIn::Int(BigInt::from(id))),
                ("dept", CellIn::Int(BigInt::from(dept))),
                ("salary", CellIn::Rational(BigInt::from(sal), BigInt::from(1))),
                ("rate", CellIn::Int(BigInt::from(rate))),
                ("hours", CellIn::Int(BigInt::from(hours))),
            ]
        })
        .collect();
    db.insert_many("emp", rows)?; // blinded locally, one round trip

    println!("SUM(salary)        = {:?}", db.sum("emp", "salary", all())?); // Int(24000)
    println!("SUM(salary) dept=5 = {:?}", db.sum("emp", "salary", eq_int("dept", 5))?); // Int(17000)
    println!("DOT(rate, hours)   = {:?}", db.dot("emp", "rate", "hours", all())?); // Int(5900)
    println!("COUNT(*)           = {}", db.count("emp", all())?); // 3

    // dialect v0.6 arithmetic expressions: exact, products of any depth (one owner round per level), division
    println!("rate*hours/2       = {:?}", db.expr("emp", "rate * hours / 2", all())?); // Rows: 1000, 1050, 900
    println!("rate*hours*rate    = {:?}", db.expr("emp", "rate * hours * rate", all())?); // depth 2: two Pi_mult rounds
    println!("SUM(rate*hours)/N  = {:?}", db.expr("emp", "SUM(rate * hours) / COUNT(*)", all())?); // Rational(5900, 3)
    println!("cost of last expr  = {:?}", db.last_expr_cost());

    // all-or-nothing, on the server AND in the local mask vault
    db.transaction(|db| db.update("emp", vec![("salary", CellIn::Int(BigInt::from(8500)))], eq_int("id", 1)))?;

    // self-join: employees of the same dept
    let step = JoinStep::new("emp", "dept", "dept").alias("b");
    let j = db.join("emp", &[step], &JoinOptions { alias: Some("a".into()), ..Default::default() })?;
    println!("self-join rows = {}, SUM(b.salary) = {:?}", j.count(), db.join_sum(&j, "b", "salary")?);
    Ok(())
}
