#[macro_use]
extern crate criterion;
extern crate clarity;
extern crate num256;

use clarity::{PrivateKey, Transaction};
use criterion::Criterion;
use num256::Uint256;

fn tx_sign_bench(c: &mut Criterion) {
    let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
        .parse()
        .unwrap();
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: "1000000000000".parse().unwrap(),
        gas_limit: "10000".parse().unwrap(),
        to: "13978aee95f38490e9769c39b2773ed763d9cd5f".parse().unwrap(),
        value: "10000000000000000".parse().unwrap(),
        data: Vec::new(),
        signature: None,
    };
    c.bench_function("sign tx without network id", move |b| {
        b.iter(|| tx.sign(&key, None))
    });
}

criterion_group!(benches, tx_sign_bench);
criterion_main!(benches);
