//! Callbacks the context hands out, and the [`Listener`] that keeps one.

use std::boxed::Box;
#[cfg(feature = "musliweb04")]
use std::cell::RefCell;
#[cfg(feature = "musliweb04")]
use std::rc::Rc;
use std::vec::Vec;

use yew::Callback;

/// Keeps a callback given to [`AuthContext`](super::AuthContext) called, such
/// as by [`subscribe_users`](super::AuthContext::subscribe_users), until it
/// is dropped. A struct component keeps it in a field.
#[must_use = "the callback is no longer called once the listener is dropped"]
pub struct Listener {
    remove: Option<Box<dyn FnOnce()>>,
}

impl Listener {
    pub(super) fn new(remove: impl FnOnce() + 'static) -> Self {
        Self {
            remove: Some(Box::new(remove)),
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(remove) = self.remove.take() {
            remove();
        }
    }
}

/// The callbacks listening for a `T`, by the id each was given.
pub(super) struct Slots<T> {
    next: u64,
    callbacks: Vec<(u64, Callback<T>)>,
}

impl<T> Default for Slots<T> {
    fn default() -> Self {
        Self {
            next: 0,
            callbacks: Vec::new(),
        }
    }
}

impl<T> Slots<T> {
    /// Adds `callback`, returning the id that removes it.
    pub(super) fn insert(&mut self, callback: Callback<T>) -> u64 {
        let id = self.next;
        self.next += 1;
        self.callbacks.push((id, callback));
        id
    }

    pub(super) fn remove(&mut self, id: u64) {
        self.callbacks.retain(|(other, _)| *other != id);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.callbacks.is_empty()
    }

    /// The callbacks, to call once nothing is borrowed: a callback may
    /// re-enter, such as a component that subscribes in its update.
    pub(super) fn callbacks(&self) -> Vec<Callback<T>> {
        self.callbacks
            .iter()
            .map(|(_, callback)| callback.clone())
            .collect()
    }
}

/// Callbacks listening for a `T`, shared by clones. Equal when shared.
#[cfg(feature = "musliweb04")]
pub(super) struct Subscribers<T> {
    inner: Rc<RefCell<Slots<T>>>,
}

#[cfg(feature = "musliweb04")]
impl<T> Default for Subscribers<T> {
    fn default() -> Self {
        Self {
            inner: Rc::default(),
        }
    }
}

#[cfg(feature = "musliweb04")]
impl<T> Clone for Subscribers<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(feature = "musliweb04")]
impl<T> PartialEq for Subscribers<T> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }
}

#[cfg(feature = "musliweb04")]
impl<T> Subscribers<T>
where
    T: Clone + 'static,
{
    /// Calls `callback` with each value [emitted](Self::emit) until the
    /// listener is dropped.
    pub(super) fn subscribe(&self, callback: Callback<T>) -> Listener {
        let id = self.inner.borrow_mut().insert(callback);
        let inner = Rc::downgrade(&self.inner);

        Listener::new(move || {
            if let Some(inner) = inner.upgrade() {
                inner.borrow_mut().remove(id);
            }
        })
    }

    /// Calls every callback with `value`.
    pub(super) fn emit(&self, value: T) {
        let callbacks = self.inner.borrow().callbacks();

        for callback in callbacks {
            callback.emit(value.clone());
        }
    }
}
