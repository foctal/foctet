// Exercise the echo handler with an unavailable replay backend.
export { default } from "../build/index.js";

export class FoctetReplay {
  fetch() {
    return new Response(null, { status: 503 });
  }
}
