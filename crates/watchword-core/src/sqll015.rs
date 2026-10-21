//! sqll 0.15 `BindValue`, `Bind` and `FromColumn` for [`UserId`], [`Role`],
//! [`Access`] and [`Method`].

use sqll015::{Bind, BindValue, Code, Error, FromColumn, Index, Result, Statement, ty};

use crate::{Access, Method, Role, UserId};

#[cfg(test)]
mod tests;

/// Binds as an SQLite integer with the same bits, as watchword's `SqllStore`
/// stores ids: every id binds, and one beyond `i64::MAX` binds as a negative
/// integer that no stored user has.
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll015")))]
impl BindValue for UserId {
    #[inline]
    fn bind_value(&self, stmt: &mut Statement, index: Index) -> Result<()> {
        (self.0 as i64).bind_value(stmt, index)
    }
}

/// Binds as the statement's only parameter, as [`BindValue`] does.
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll015")))]
impl Bind for UserId {
    const COUNT: usize = 1;

    #[inline]
    fn bind(&self, stmt: &mut Statement) -> Result<()> {
        self.bind_value(stmt, Index::BIND)
    }
}

/// Reads an integer column with the same bits, the reverse of [`BindValue`].
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll015")))]
impl FromColumn<'_> for UserId {
    type Type = ty::Integer;

    #[inline]
    fn from_column(stmt: &Statement, index: ty::Integer) -> Result<Self> {
        Ok(UserId(i64::from_column(stmt, index)? as u64))
    }
}

/// Implements sqll's traits for a fieldless enum through its stored name.
macro_rules! named {
    ($ty:ident, $what:literal) => {
        #[doc = concat!("Binds the ", $what, "'s name, [`", stringify!($ty), "::as_str`], as text.")]
        #[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll015")))]
        impl BindValue for $ty {
            #[inline]
            fn bind_value(&self, stmt: &mut Statement, index: Index) -> Result<()> {
                self.as_str().bind_value(stmt, index)
            }
        }

        /// Binds as the statement's only parameter, as [`BindValue`] does.
        #[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll015")))]
        impl Bind for $ty {
            const COUNT: usize = 1;

            #[inline]
            fn bind(&self, stmt: &mut Statement) -> Result<()> {
                self.bind_value(stmt, Index::BIND)
            }
        }

        #[doc = concat!("Reads a text column holding the ", $what, "'s name, failing with")]
        #[doc = concat!("[`Code::MISMATCH`] on a name that is not one.")]
        #[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll015")))]
        impl<'stmt> FromColumn<'stmt> for $ty {
            type Type = ty::Text;

            #[inline]
            fn from_column(stmt: &'stmt Statement, index: ty::Text) -> Result<Self> {
                let name = <&str>::from_column(stmt, index)?;

                name.parse().map_err(|_| {
                    Error::new(
                        Code::MISMATCH,
                        format_args!(concat!("unknown ", $what, " {:?}"), name),
                    )
                })
            }
        }
    };
}

named!(Role, "role");
named!(Access, "access state");
named!(Method, "sign-in method");
