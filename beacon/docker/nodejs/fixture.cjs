// An ordinary application: no telemetry imports or SDK initialization.
const http = require('node:http');
const server = http.createServer((request, response) => {
  console.log(`TRACEPARENT ${request.headers.traceparent}`);
  let total = 0;
  for (let index = 0; index < 100000; index++) total += Math.sqrt(index);
  response.end(String(total));
});
server.listen(0, '127.0.0.1', () => {
  http
    .get(
      `http://127.0.0.1:${server.address().port}/beacon-image-smoke`,
      response => {
        response.resume();
        response.on('end', () => setTimeout(() => server.close(), 5500));
      }
    )
    .on('error', error => {
      throw error;
    });
});
