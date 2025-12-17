export const errorHandler = (err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  } else {
    const status = err.status || 500;

    res.status(status).send({
      message: err.message || 'Internal server error',
    });
  }
};
