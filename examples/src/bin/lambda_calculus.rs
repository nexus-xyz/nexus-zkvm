#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;

use alloc::{boxed::Box, string::ToString};
use core::fmt::{Debug, Display};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct DeBruijnIndex(usize);

impl From<usize> for DeBruijnIndex {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl Display for DeBruijnIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug)]
enum Term<R> {
    Var(DeBruijnIndex),
    Lambda(R),
    Apply(R, R),
}

impl<R: Display> Display for Term<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Term::Var(v) => write!(f, "{v}"),
            // The following cases may be simplified when
            // https://github.com/nexus-xyz/nexus-zkvm/issues/153 is resolved.
            Term::Lambda(t) => {
                write!(f, "(\\")?;
                write!(f, "{t}")?;
                write!(f, ")")
            }
            Term::Apply(t1, t2) => {
                write!(f, "(")?;
                write!(f, "{t1}")?;
                write!(f, " ")?;
                write!(f, "{t2}")?;
                write!(f, ")")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Expr(Term<Box<Self>>);

impl Display for Expr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for Expr {
    fn eq(&self, other: &Self) -> bool {
        self.clone().eval().structural_eq(&other.clone().eval())
    }
}

impl Eq for Expr {}

impl Expr {
    pub fn var<T: Into<DeBruijnIndex>>(binding: T) -> Self {
        Self(Term::Var(binding.into()))
    }

    pub fn lambda<T: Into<Box<Self>>>(inner: T) -> Self {
        Self(Term::Lambda(inner.into()))
    }

    pub fn apply<T1, T2>(left: T1, right: T2) -> Self
    where
        T1: Into<Box<Self>>,
        T2: Into<Box<Self>>,
    {
        Self(Term::Apply(left.into(), right.into()))
    }

    pub fn identity() -> Self {
        Self::lambda(Self::var(0))
    }

    pub fn omega() -> Self {
        let expr = Self::lambda(Self::apply(Self::var(0), Self::var(0)));
        Self::apply(expr.clone(), expr)
    }

    pub fn step(&self) -> Self {
        fn subst(body: Expr, arg: Expr, depth: usize) -> Expr {
            match body.0 {
                Term::Var(i) => {
                    if i.0 == depth {
                        arg
                    } else {
                        Expr::var(i)
                    }
                }
                Term::Lambda(e) => subst(*e, arg, depth + 1),
                Term::Apply(e1, e2) => {
                    Expr::apply(subst(*e1, arg.clone(), depth), subst(*e2, arg, depth))
                }
            }
        }

        // attempt beta reduction
        if let Term::Apply(e1, e2) = &self.0 {
            if let Term::Lambda(e) = &e1.0 {
                return subst(*e.clone(), *e2.clone(), 0);
            }
        }

        self.clone()
    }

    pub fn structural_eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Term::Var(i), Term::Var(j)) => *i == *j,
            (Term::Lambda(e), Term::Lambda(f)) => e.structural_eq(f),
            (Term::Apply(e1, e2), Term::Apply(f1, f2)) => {
                e1.structural_eq(f1) && e2.structural_eq(f2)
            }
            _ => false,
        }
    }

    pub fn eval(self) -> Self {
        let mut curr = self;
        loop {
            let next = curr.step();
            if next.structural_eq(&curr) {
                return curr.clone();
            } else {
                curr = next;
            }
        }
    }
}

#[nexus_rt::main]
fn main() {
    assert_eq!(Expr::identity().to_string(), r#"(\0)"#);
    assert_eq!(Expr::omega().to_string(), r#"((\(0 0)) (\(0 0)))"#);
    assert_eq!(Expr::var(0).eval(), Expr::var(0));

    assert_eq!(
        Expr::apply(Expr::identity(), Expr::var(42)).step(),
        Expr::var(42)
    );

    assert_eq!(Expr::omega().step(), Expr::omega());
}
