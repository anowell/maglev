use axum::{handler::Handler, routing, Router};

pub struct CrudRouter<S> {
    router: Router<S>,
}

impl<S> Default for CrudRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> CrudRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        CrudRouter {
            router: Router::new(),
        }
    }

    pub fn list<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.router = self.router.route("/", routing::get(handler));
        self
    }

    pub fn create<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.router = self.router.route("/", routing::post(handler));
        self
    }

    pub fn read<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.router = self.router.route("/:id", routing::get(handler));
        self
    }

    pub fn update<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.router = self.router.route("/:id", routing::patch(handler));
        self
    }

    pub fn replace<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.router = self.router.route("/:id", routing::put(handler));
        self
    }

    pub fn delete<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.router = self.router.route("/:id", routing::delete(handler));
        self
    }

    pub fn into_router(self) -> Router<S> {
        self.router
    }
}
