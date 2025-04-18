// Copyright 2012-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support code for rustc's built in unit-test and micro-benchmarking
//! framework.
//!
//! Almost all user code will only be interested in `Bencher` and
//! `black_box`. All other interactions (such as writing tests and
//! benchmarks themselves) should be done via the `#[test]` and
//! `#[bench]` attributes.
//!
//! See the [Testing Chapter](../book/testing.html) of the book for more details.

// Currently, not much of this is meant for users. It is intended to
// support the simplest interface possible for representing and
// running tests while providing a base that other test frameworks may
// build off of.

extern crate libc;
pub use self::ColorConfig::*;
use self::NamePadding::*;
use self::OutputLocation::*;
use self::TestEvent::*;
pub use self::TestFn::*;
pub use self::TestName::*;
pub use self::TestResult::*;
use std::any::Any;
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

// The name of a test. By convention this follows the rules for rust
// paths; i.e. it should be a series of identifiers separated by double
// colons. This way if some test runner wants to arrange the tests
// hierarchically it may.

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum TestName {
    DynTestName(String),
}
impl TestName {
    fn as_slice(&self) -> &str {
        match *self {
            DynTestName(ref s) => s,
        }
    }
}
impl fmt::Display for TestName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_slice(), f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NamePadding {
    PadNone,
    PadOnRight,
}

impl TestDesc {
    pub fn new(name: TestName) -> Self {
        TestDesc {
            name,
            ignore: false,
            should_panic: ShouldPanic::No,
        }
    }

    fn padded_name(&self, column_count: usize, align: NamePadding) -> String {
        let mut name = String::from(self.name.as_slice());
        let fill = column_count.saturating_sub(name.len());
        let pad = std::iter::repeat_n(" ", fill).collect::<String>();
        match align {
            PadNone => name,
            PadOnRight => {
                name.push_str(&pad);
                name
            }
        }
    }
}

// A function that runs a test. If the function returns successfully,
// the test succeeds; if the function panics then the test fails. We
// may need to come up with a more clever definition of test in order
// to support isolation of tests into threads.
pub enum TestFn {
    DynTest(Box<dyn FnMut() + Send>),
}

impl TestFn {
    fn padding(&self) -> NamePadding {
        match *self {
            DynTest(..) => PadNone,
        }
    }
}

impl fmt::Debug for TestFn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            DynTest(..) => "DynTestFn(..)",
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ShouldPanic {
    No,
    Yes,
}

// The definition of a single test. A test runner will run a list of
// these.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TestDesc {
    pub name: TestName,
    pub ignore: bool,
    pub should_panic: ShouldPanic,
}

unsafe impl Send for TestDesc {}

#[derive(Debug)]
pub struct TestDescAndFn {
    pub desc: TestDesc,
    pub testfn: TestFn,
}

#[derive(Clone, PartialEq, Debug, Copy)]
pub struct Metric {
    value: f64,
    noise: f64,
}

#[derive(PartialEq)]
pub struct MetricMap(BTreeMap<String, Metric>);

impl Clone for MetricMap {
    fn clone(&self) -> MetricMap {
        let MetricMap(ref map) = *self;
        MetricMap(map.clone())
    }
}

// The default console test runner. It accepts the command line
// arguments and a vector of test_descs.
pub fn test_main(args: &[String], tests: Vec<TestDescAndFn>) {
    let opts = match parse_opts(args) {
        Some(Ok(o)) => o,
        Some(Err(msg)) => panic!("{:?}", msg),
        None => return,
    };
    match run_tests_console(&opts, tests) {
        Ok(true) => {}
        Ok(false) => std::process::exit(101),
        Err(e) => panic!("io error when running tests: {:?}", e),
    }
}

#[derive(Copy, Clone)]
pub enum ColorConfig {
    Auto,
    Always,
    Never,
}

pub struct TestOpts {
    pub filter: Option<String>,
    pub run_ignored: bool,
    pub run_tests: bool,
    pub bench_benchmarks: bool,
    pub logfile: Option<PathBuf>,
    pub nocapture: bool,
    pub color: ColorConfig,
    pub verbose: bool,
}

/// Result of parsing the options.
pub type OptRes = Result<TestOpts, String>;

#[rustfmt::skip]
fn options() -> getopts::Options {
    let mut opts = getopts::Options::new();
    opts.optflag("", "ignored", "Run ignored tests")
        .optflag("", "test", "Run tests and not benchmarks")
        .optflag("", "bench", "Run benchmarks instead of tests")
        .optflag("h", "help", "Display this message (longer with --help)")
        .optopt("", "logfile", "Write logs to the specified file instead \
                     of stdout", "PATH");
    opts.optopt("", "color", "Configure coloring of output:
            auto   = colorize if stdout is a tty and tests are run on serially (default);
            always = always colorize output;
            never  = never colorize output;", "auto|always|never")
        .optflag("v", "verbose", "Display the name of each test when it starts");
    opts
}

fn usage(binary: &str) {
    let message = format!("Usage: {} [OPTIONS] [FILTER]", binary);
    println!(
        r#"{usage}

The FILTER string is tested against the name of all tests, and only those
tests whose names contain the filter are run.

By default, all tests are run in parallel. This can be altered with the
RUST_TEST_THREADS environment variable when running tests (set it to 1).
"#,
        usage = options().usage(&message)
    );
}

// Parses command line arguments into test options
pub fn parse_opts(args: &[String]) -> Option<OptRes> {
    let args_ = &args[1..];
    let matches = match options().parse(args_) {
        Ok(m) => m,
        Err(f) => return Some(Err(f.to_string())),
    };

    if matches.opt_present("h") {
        usage(&args[0]);
        return None;
    }

    let filter = if !matches.free.is_empty() {
        Some(matches.free[0].clone())
    } else {
        None
    };

    let run_ignored = matches.opt_present("ignored");
    let verbose = matches.opt_present("verbose");

    let logfile = matches.opt_str("logfile");
    let logfile = logfile.map(|s| PathBuf::from(&s));

    let bench_benchmarks = matches.opt_present("bench");
    let run_tests = !bench_benchmarks || matches.opt_present("test");

    let mut nocapture = false;

    if !nocapture {
        nocapture = env::var("RUST_TEST_NOCAPTURE").is_ok();
    }

    let color = match matches.opt_str("color").as_deref() {
        Some("auto") | None => Auto,
        Some("always") => Always,
        Some("never") => Never,

        Some(v) => {
            return Some(Err(format!(
                "argument for --color must be auto, always, or never (was \
                                     {})",
                v
            )))
        }
    };

    let test_opts = TestOpts {
        filter,
        run_ignored,
        run_tests,
        bench_benchmarks,
        logfile,
        nocapture,
        color,
        verbose,
    };

    Some(Ok(test_opts))
}

#[derive(Clone, PartialEq)]
pub struct BenchSamples {
    ns_iter_summ: crate::stats::Summary,
    mb_s: usize,
}

#[derive(Clone, PartialEq)]
pub enum TestResult {
    TrOk,
    Failed,
    Ignored,
}

unsafe impl Send for TestResult {}

enum OutputLocation<T> {
    Pretty(Box<term::StdoutTerminal>),
    Raw(T),
}

struct ConsoleTestState<T> {
    log_out: Option<File>,
    out: OutputLocation<T>,
    use_color: bool,
    verbose: bool,
    total: usize,
    passed: usize,
    failed: usize,
    ignored: usize,
    measured: usize,
    failures: Vec<(TestDesc, Vec<u8>)>,
    max_name_len: usize, // number of columns to fill when aligning names
}

impl<T: Write> ConsoleTestState<T> {
    pub fn new(opts: &TestOpts, _: Option<T>) -> io::Result<ConsoleTestState<io::Stdout>> {
        let log_out = match opts.logfile {
            Some(ref path) => Some(File::create(path)?),
            None => None,
        };
        let out = match term::stdout() {
            None => Raw(io::stdout()),
            Some(t) => Pretty(t),
        };

        Ok(ConsoleTestState {
            out,
            log_out,
            use_color: use_color(opts),
            verbose: opts.verbose,
            total: 0,
            passed: 0,
            failed: 0,
            ignored: 0,
            measured: 0,
            failures: Vec::new(),
            max_name_len: 0,
        })
    }

    pub fn write_ok(&mut self) -> io::Result<()> {
        self.write_short_result("ok", ".", term::color::GREEN)
    }

    pub fn write_failed(&mut self) -> io::Result<()> {
        self.write_short_result("FAILED", "F", term::color::RED)
    }

    pub fn write_ignored(&mut self) -> io::Result<()> {
        self.write_short_result("ignored", "i", term::color::YELLOW)
    }

    pub fn write_short_result(
        &mut self,
        verbose: &str,
        quiet: &str,
        color: term::color::Color,
    ) -> io::Result<()> {
        if self.verbose {
            self.write_pretty(verbose, color)?;
            self.write_plain("\n")
        } else {
            self.write_pretty(quiet, color)
        }
    }

    pub fn write_pretty(&mut self, word: &str, color: term::color::Color) -> io::Result<()> {
        match self.out {
            Pretty(ref mut term) => {
                if self.use_color {
                    term.fg(color)?;
                }
                term.write_all(word.as_bytes())?;
                if self.use_color {
                    term.reset()?;
                }
                term.flush()
            }
            Raw(ref mut stdout) => {
                stdout.write_all(word.as_bytes())?;
                stdout.flush()
            }
        }
    }

    pub fn write_plain(&mut self, s: &str) -> io::Result<()> {
        match self.out {
            Pretty(ref mut term) => {
                term.write_all(s.as_bytes())?;
                term.flush()
            }
            Raw(ref mut stdout) => {
                stdout.write_all(s.as_bytes())?;
                stdout.flush()
            }
        }
    }

    pub fn write_run_start(&mut self, len: usize) -> io::Result<()> {
        self.total = len;
        let noun = if len != 1 { "tests" } else { "test" };
        self.write_plain(&format!("\nrunning {} {}\n", len, noun))
    }

    pub fn write_test_start(&mut self, test: &TestDesc, align: NamePadding) -> io::Result<()> {
        if self.verbose || align == PadOnRight {
            let name = test.padded_name(self.max_name_len, align);
            self.write_plain(&format!("test {} ... ", name))
        } else {
            Ok(())
        }
    }

    pub fn write_result(&mut self, result: &TestResult) -> io::Result<()> {
        match *result {
            TrOk => self.write_ok(),
            Failed => self.write_failed(),
            Ignored => self.write_ignored(),
        }
    }

    pub fn write_log(&mut self, test: &TestDesc, result: &TestResult) -> io::Result<()> {
        match self.log_out {
            None => Ok(()),
            Some(ref mut o) => {
                let s = format!(
                    "{} {}\n",
                    match *result {
                        TrOk => "ok".to_owned(),
                        Failed => "failed".to_owned(),
                        Ignored => "ignored".to_owned(),
                    },
                    test.name
                );
                o.write_all(s.as_bytes())
            }
        }
    }

    pub fn write_failures(&mut self) -> io::Result<()> {
        self.write_plain("\nfailures:\n")?;
        let mut failures = Vec::new();
        let mut fail_out = String::new();
        for (f, stdout) in &self.failures {
            failures.push(f.name.to_string());
            if !stdout.is_empty() {
                fail_out.push_str(&format!("---- {} stdout ----\n\t", f.name));
                let output = String::from_utf8_lossy(stdout);
                fail_out.push_str(&output);
                fail_out.push('\n');
            }
        }
        if !fail_out.is_empty() {
            self.write_plain("\n")?;
            self.write_plain(&fail_out)?;
        }

        self.write_plain("\nfailures:\n")?;
        failures.sort();
        for name in &failures {
            self.write_plain(&format!("    {}\n", name))?;
        }
        Ok(())
    }

    pub fn write_run_finish(&mut self) -> io::Result<bool> {
        assert!(self.passed + self.failed + self.ignored + self.measured == self.total);

        let success = self.failed == 0;
        if !success {
            self.write_failures()?;
        }

        self.write_plain("\ntest result: ")?;
        if success {
            // There's no parallelism at this point so it's safe to use color
            self.write_pretty("ok", term::color::GREEN)?;
        } else {
            self.write_pretty("FAILED", term::color::RED)?;
        }
        let s = format!(
            ". {} passed; {} failed; {} ignored; {} measured\n\n",
            self.passed, self.failed, self.ignored, self.measured
        );
        self.write_plain(&s)?;
        Ok(success)
    }
}

// A simple console test runner
pub fn run_tests_console(opts: &TestOpts, tests: Vec<TestDescAndFn>) -> io::Result<bool> {
    fn callback<T: Write>(event: &TestEvent, st: &mut ConsoleTestState<T>) -> io::Result<()> {
        match (*event).clone() {
            Filtered(ref filtered_tests) => st.write_run_start(filtered_tests.len()),
            Wait(ref test, padding) => st.write_test_start(test, padding),
            TeResult(test, result, stdout) => {
                st.write_log(&test, &result)?;
                st.write_result(&result)?;
                match result {
                    TrOk => st.passed += 1,
                    Ignored => st.ignored += 1,
                    Failed => {
                        st.failed += 1;
                        st.failures.push((test, stdout));
                    }
                }
                Ok(())
            }
        }
    }

    let mut st = ConsoleTestState::new(opts, None::<io::Stdout>)?;
    fn len_if_padded(t: &TestDescAndFn) -> usize {
        match t.testfn.padding() {
            PadNone => 0,
            PadOnRight => t.desc.name.as_slice().len(),
        }
    }
    if let Some(t) = tests.iter().max_by_key(|t| len_if_padded(t)) {
        let n = t.desc.name.as_slice();
        st.max_name_len = n.len();
    }
    run_tests(opts, tests, |x| callback(&x, &mut st))?;
    st.write_run_finish()
}

#[test]
fn should_sort_failures_before_printing_them() {
    let test_a = TestDesc {
        name: StaticTestName("a"),
        ignore: false,
        should_panic: ShouldPanic::No,
        ..TestDesc::default()
    };

    let test_b = TestDesc {
        name: StaticTestName("b"),
        ignore: false,
        should_panic: ShouldPanic::No,
        ..TestDesc::default()
    };

    let mut st = ConsoleTestState {
        log_out: None,
        out: Raw(Vec::new()),
        use_color: false,
        verbose: false,
        total: 0,
        passed: 0,
        failed: 0,
        ignored: 0,
        measured: 0,
        max_name_len: 10,
        failures: vec![(test_b, Vec::new()), (test_a, Vec::new())],
    };

    st.write_failures().unwrap();
    let s = match st.out {
        Raw(ref m) => String::from_utf8_lossy(&m[..]),
        Pretty(_) => unreachable!(),
    };

    let apos = s.find("a").unwrap();
    let bpos = s.find("b").unwrap();
    assert!(apos < bpos);
}

fn use_color(opts: &TestOpts) -> bool {
    match opts.color {
        Auto => !opts.nocapture && stdout_isatty(),
        Always => true,
        Never => false,
    }
}

#[cfg(unix)]
fn stdout_isatty() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
}

#[derive(Clone)]
enum TestEvent {
    Filtered(Vec<TestDesc>),
    Wait(TestDesc, NamePadding),
    TeResult(TestDesc, TestResult, Vec<u8>),
}

pub type MonitorMsg = (TestDesc, TestResult, Vec<u8>);

fn run_tests<F>(opts: &TestOpts, tests: Vec<TestDescAndFn>, mut callback: F) -> io::Result<()>
where
    F: FnMut(TestEvent) -> io::Result<()>,
{
    let mut filtered_tests = filter_tests(opts, tests);
    if !opts.bench_benchmarks {
        filtered_tests = convert_benchmarks_to_tests(filtered_tests);
    }

    let filtered_descs = filtered_tests.iter().map(|t| t.desc.clone()).collect();

    callback(Filtered(filtered_descs))?;

    let (filtered_tests, filtered_benchs_and_metrics): (Vec<_>, _) = filtered_tests
        .into_iter()
        .partition(|e| matches!(e.testfn, DynTest(_)));

    // It's tempting to just spawn all the tests at once, but since we have
    // many tests that run in other processes we would be making a big mess.
    let concurrency = 8;

    let mut remaining = filtered_tests;
    remaining.reverse();
    let mut pending = 0;

    let (tx, rx) = channel::<MonitorMsg>();

    while pending > 0 || !remaining.is_empty() {
        while pending < concurrency && !remaining.is_empty() {
            let test = remaining.pop().unwrap();
            if concurrency == 1 {
                // We are doing one test at a time so we can print the name
                // of the test before we run it. Useful for debugging tests
                // that hang forever.
                callback(Wait(test.desc.clone(), test.testfn.padding()))?;
            }
            run_test(opts, !opts.run_tests, test, tx.clone());
            pending += 1;
        }

        let (desc, result, stdout) = rx.recv().unwrap();
        if concurrency != 1 {
            callback(Wait(desc.clone(), PadNone))?;
        }
        callback(TeResult(desc, result, stdout))?;
        pending -= 1;
    }

    if opts.bench_benchmarks {
        // All benchmarks run at the end, in serial.
        // (this includes metric fns)
        for b in filtered_benchs_and_metrics {
            callback(Wait(b.desc.clone(), b.testfn.padding()))?;
            run_test(opts, false, b, tx.clone());
            let (test, result, stdout) = rx.recv().unwrap();
            callback(TeResult(test, result, stdout))?;
        }
    }
    Ok(())
}

pub fn filter_tests(opts: &TestOpts, tests: Vec<TestDescAndFn>) -> Vec<TestDescAndFn> {
    let mut filtered = tests;

    // Remove tests that don't match the test filter
    filtered = match opts.filter {
        None => filtered,
        Some(ref filter) => filtered
            .into_iter()
            .filter(|test| test.desc.name.as_slice().contains(&filter[..]))
            .collect(),
    };

    // Maybe pull out the ignored test and unignore them
    filtered = if !opts.run_ignored {
        filtered
    } else {
        fn filter(test: TestDescAndFn) -> Option<TestDescAndFn> {
            if test.desc.ignore {
                let TestDescAndFn { desc, testfn } = test;
                Some(TestDescAndFn {
                    desc: TestDesc {
                        ignore: false,
                        ..desc
                    },
                    testfn,
                })
            } else {
                None
            }
        }
        filtered.into_iter().filter_map(filter).collect()
    };

    // Sort the tests alphabetically
    filtered.sort_by(|t1, t2| t1.desc.name.as_slice().cmp(t2.desc.name.as_slice()));

    filtered
}

pub fn convert_benchmarks_to_tests(tests: Vec<TestDescAndFn>) -> Vec<TestDescAndFn> {
    // convert benchmarks to tests, if we're not benchmarking them
    tests
        .into_iter()
        .map(|x| {
            let f = x.testfn;
            let testfn = f;
            TestDescAndFn {
                desc: x.desc,
                testfn,
            }
        })
        .collect()
}

pub fn run_test(
    opts: &TestOpts,
    force_ignore: bool,
    test: TestDescAndFn,
    monitor_ch: Sender<MonitorMsg>,
) {
    let TestDescAndFn { desc, testfn } = test;

    if force_ignore || desc.ignore {
        monitor_ch.send((desc, Ignored, Vec::new())).unwrap();
        return;
    }

    fn run_test_inner(
        desc: TestDesc,
        monitor_ch: Sender<MonitorMsg>,
        nocapture: bool,
        mut testfn: Box<dyn FnMut() + Send>,
    ) {
        thread::spawn(move || {
            let data = Arc::new(Mutex::new(Vec::new()));
            let data2 = data.clone();
            let cfg = thread::Builder::new().name(match desc.name {
                DynTestName(ref name) => name.clone(),
            });

            fn capture(_data2: Arc<Mutex<Vec<u8>>>) {}

            let result_guard = cfg
                .spawn(move || {
                    if !nocapture {
                        capture(data2)
                    }
                    testfn()
                })
                .unwrap();
            let test_result = calc_result(&desc, result_guard.join());
            let stdout = data.lock().unwrap().to_vec();
            monitor_ch
                .send((desc.clone(), test_result, stdout))
                .unwrap();
        });
    }

    match testfn {
        DynTest(f) => run_test_inner(desc, monitor_ch, opts.nocapture, f),
    }
}

fn calc_result(desc: &TestDesc, task_result: Result<(), Box<dyn Any + Send>>) -> TestResult {
    match (&desc.should_panic, task_result) {
        (&ShouldPanic::No, Ok(())) | (&ShouldPanic::Yes, Err(_)) => TrOk,
        _ => Failed,
    }
}

#[cfg(test)]
mod tests {

    #[test]
    pub fn do_not_run_ignored_tests() {
        fn f() {
            panic!();
        }
        let desc = TestDescAndFn {
            desc: TestDesc {
                name: StaticTestName("whatever"),
                ignore: true,
                should_panic: ShouldPanic::No,
                ..TestDesc::default()
            },
            testfn: DynTestFn(Box::new(move || f())),
        };
        let (tx, rx) = channel();
        run_test(&TestOpts::new(), false, desc, tx);
        let (_, res, _) = rx.recv().unwrap();
        assert!(res != TrOk);
    }

    #[test]
    pub fn ignored_tests_result_in_ignored() {
        fn f() {}
        let desc = TestDescAndFn {
            desc: TestDesc {
                name: StaticTestName("whatever"),
                ignore: true,
                should_panic: ShouldPanic::No,
                ..TestDesc::default()
            },
            testfn: DynTestFn(Box::new(move || f())),
        };
        let (tx, rx) = channel();
        run_test(&TestOpts::new(), false, desc, tx);
        let (_, res, _) = rx.recv().unwrap();
        assert!(res == TrIgnored);
    }

    #[test]
    fn test_should_panic() {
        fn f() {
            panic!();
        }
        let desc = TestDescAndFn {
            desc: TestDesc {
                name: StaticTestName("whatever"),
                ignore: false,
                should_panic: ShouldPanic::Yes,
                ..TestDesc::default()
            },
            testfn: DynTestFn(Box::new(move || f())),
        };
        let (tx, rx) = channel();
        run_test(&TestOpts::new(), false, desc, tx);
        let (_, res, _) = rx.recv().unwrap();
        assert!(res == TrOk);
    }

    #[test]
    fn test_should_panic_good_message() {
        fn f() {
            panic!("an error message");
        }
        let desc = TestDescAndFn {
            desc: TestDesc {
                name: StaticTestName("whatever"),
                ignore: false,
                should_panic: ShouldPanic::YesWithMessage("error message"),
                ..TestDesc::default()
            },
            testfn: DynTestFn(Box::new(move || f())),
        };
        let (tx, rx) = channel();
        run_test(&TestOpts::new(), false, desc, tx);
        let (_, res, _) = rx.recv().unwrap();
        assert!(res == TrOk);
    }

    #[test]
    fn test_should_panic_bad_message() {
        fn f() {
            panic!("an error message");
        }
        let desc = TestDescAndFn {
            desc: TestDesc {
                name: StaticTestName("whatever"),
                ignore: false,
                should_panic: ShouldPanic::YesWithMessage("foobar"),
                ..TestDesc::default()
            },
            testfn: DynTestFn(Box::new(move || f())),
        };
        let (tx, rx) = channel();
        run_test(&TestOpts::new(), false, desc, tx);
        let (_, res, _) = rx.recv().unwrap();
        assert!(res == TrFailed);
    }

    #[test]
    fn test_should_panic_but_succeeds() {
        fn f() {}
        let desc = TestDescAndFn {
            desc: TestDesc {
                name: StaticTestName("whatever"),
                ignore: false,
                should_panic: ShouldPanic::Yes,
                ..TestDesc::default()
            },
            testfn: DynTestFn(Box::new(move || f())),
        };
        let (tx, rx) = channel();
        run_test(&TestOpts::new(), false, desc, tx);
        let (_, res, _) = rx.recv().unwrap();
        assert!(res == TrFailed);
    }

    #[test]
    fn parse_ignored_flag() {
        let args = vec![
            "progname".to_string(),
            "filter".to_string(),
            "--ignored".to_string(),
        ];
        let opts = match parse_opts(&args) {
            Some(Ok(o)) => o,
            _ => panic!("Malformed arg in parse_ignored_flag"),
        };
        assert!((opts.run_ignored));
    }

    #[test]
    pub fn filter_for_ignored_option() {
        // When we run ignored tests the test filter should filter out all the
        // unignored tests and flip the ignore flag on the rest to false

        let mut opts = TestOpts::new();
        opts.run_tests = true;
        opts.run_ignored = true;

        let tests = vec![
            TestDescAndFn {
                desc: TestDesc {
                    name: StaticTestName("1"),
                    ignore: true,
                    should_panic: ShouldPanic::No,
                    ..TestDesc::default()
                },
                testfn: DynTestFn(Box::new(move || {})),
            },
            TestDescAndFn {
                desc: TestDesc {
                    name: StaticTestName("2"),
                    ignore: false,
                    should_panic: ShouldPanic::No,
                    ..TestDesc::default()
                },
                testfn: DynTestFn(Box::new(move || {})),
            },
        ];
        let filtered = filter_tests(&opts, tests);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].desc.name.to_string(), "1");
        assert!(filtered[0].desc.ignore == false);
    }

    #[test]
    pub fn sort_tests() {
        let mut opts = TestOpts::new();
        opts.run_tests = true;

        let names = vec![
            "sha1::test".to_string(),
            "isize::test_to_str".to_string(),
            "isize::test_pow".to_string(),
            "test::do_not_run_ignored_tests".to_string(),
            "test::ignored_tests_result_in_ignored".to_string(),
            "test::first_free_arg_should_be_a_filter".to_string(),
            "test::parse_ignored_flag".to_string(),
            "test::filter_for_ignored_option".to_string(),
            "test::sort_tests".to_string(),
        ];
        let tests = {
            fn testfn() {}
            let mut tests = Vec::new();
            for name in &names {
                let test = TestDescAndFn {
                    desc: TestDesc {
                        name: DynTestName((*name).clone()),
                        ignore: false,
                        should_panic: ShouldPanic::No,
                        ..TestDesc::default()
                    },
                    testfn: DynTestFn(Box::new(testfn)),
                };
                tests.push(test);
            }
            tests
        };
        let filtered = filter_tests(&opts, tests);

        let expected = vec![
            "isize::test_pow".to_string(),
            "isize::test_to_str".to_string(),
            "sha1::test".to_string(),
            "test::do_not_run_ignored_tests".to_string(),
            "test::filter_for_ignored_option".to_string(),
            "test::first_free_arg_should_be_a_filter".to_string(),
            "test::ignored_tests_result_in_ignored".to_string(),
            "test::parse_ignored_flag".to_string(),
            "test::sort_tests".to_string(),
        ];

        for (a, b) in expected.iter().zip(filtered) {
            assert!(*a == b.desc.name.to_string());
        }
    }

    #[test]
    pub fn test_metricmap_compare() {
        let mut m1 = MetricMap::new();
        let mut m2 = MetricMap::new();
        m1.insert_metric("in-both-noise", 1000.0, 200.0);
        m2.insert_metric("in-both-noise", 1100.0, 200.0);

        m1.insert_metric("in-first-noise", 1000.0, 2.0);
        m2.insert_metric("in-second-noise", 1000.0, 2.0);

        m1.insert_metric("in-both-want-downwards-but-regressed", 1000.0, 10.0);
        m2.insert_metric("in-both-want-downwards-but-regressed", 2000.0, 10.0);

        m1.insert_metric("in-both-want-downwards-and-improved", 2000.0, 10.0);
        m2.insert_metric("in-both-want-downwards-and-improved", 1000.0, 10.0);

        m1.insert_metric("in-both-want-upwards-but-regressed", 2000.0, -10.0);
        m2.insert_metric("in-both-want-upwards-but-regressed", 1000.0, -10.0);

        m1.insert_metric("in-both-want-upwards-and-improved", 1000.0, -10.0);
        m2.insert_metric("in-both-want-upwards-and-improved", 2000.0, -10.0);
    }
}
