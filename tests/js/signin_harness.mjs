/**
 * Runs the sign-in page's flow outside a browser.
 *
 * `content/assets/app.js` is where phase 4's two expensive rules live — that
 * `fxaccounts:login` precedes `fxaccounts:oauth_login`, and that key material
 * is left out of the former on an OAuth flow — and neither is visible from the
 * server side.  So the page is loaded under node against just enough of a DOM
 * to run, with the WebChannel replaced by a recorder that answers the way
 * Firefox would, and a real HTTP server on the other end of `fetch`.
 *
 * What this is not is a browser: there is no layout, no CSS and no event loop
 * fidelity.  It exercises the flow, not the page.
 *
 *   node signin_harness.mjs <assets dir> <base url>  < job.json  > result.json
 */

const [assetsDir, baseUrl] = process.argv.slice(2);

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const job = await readStdin();

// --------------------------------------------------------------------------
// The smallest DOM that `app.js` can run against.
// --------------------------------------------------------------------------

const byId = new Map();

class Node {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.attributes = {};
    this.listeners = {};
    this.value = '';
    this.textContent = '';
    this.className = '';
    this.disabled = false;
  }

  setAttribute(name, value) {
    this.attributes[name] = value;
    if (name === 'value') {
      this.value = value;
    }
    if (name === 'id') {
      this.id = value;
      byId.set(value, this);
    }
  }

  addEventListener(type, handler) {
    (this.listeners[type] ||= []).push(handler);
  }

  removeEventListener(type, handler) {
    this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== handler);
  }

  async dispatchEvent(event) {
    event.target ||= this;
    for (const handler of this.listeners[event.type] || []) {
      await handler(event);
    }
  }

  append(...nodes) {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes) {
    this.children = nodes;
  }

  focus() {}

  /** Depth-first search, so the harness can find the form `app.js` built. */
  find(tagName) {
    for (const child of this.children) {
      if (child.tagName === tagName) {
        return child;
      }
      const found = child.find?.(tagName);
      if (found) {
        return found;
      }
    }
    return undefined;
  }

  get text() {
    return [this.textContent, ...this.children.map((child) => child.text ?? '')]
      .filter(Boolean)
      .join(' ');
  }
}

class Text {
  constructor(value) {
    this.textContent = value;
  }

  get text() {
    return this.textContent;
  }
}

const root = new Node('main');
root.setAttribute('id', 'app');

globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (value) => new Text(value),
  getElementById: (id) => byId.get(id),
};

globalThis.CustomEvent = class CustomEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.detail = init.detail;
  }
};

const windowListeners = {};
const url = new URL(job.path + (job.query || ''), baseUrl);

globalThis.window = {
  location: { pathname: url.pathname, search: url.search, href: url.href },
  addEventListener: (type, handler) => (windowListeners[type] ||= []).push(handler),
  removeEventListener: (type, handler) => {
    windowListeners[type] = (windowListeners[type] || []).filter((f) => f !== handler);
  },
  dispatchEvent: (event) => {
    for (const handler of [...(windowListeners[event.type] || [])]) {
      handler(event);
    }
  },
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (timer) => clearTimeout(timer),
  requestAnimationFrame: (fn) => setTimeout(fn, 0),
};

// node defines `navigator` as a getter, so it has to be redefined rather than
// assigned. `webchannel.js` reads it to tell Desktop apart from Firefox iOS.
Object.defineProperty(globalThis, 'navigator', {
  configurable: true,
  value: { userAgent: job.userAgent || 'Mozilla/5.0 Gecko/20100101 Firefox/140.0' },
});

// `api.js` fetches same-origin paths; node needs them absolute.
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => realFetch(new URL(input, baseUrl), init);

// --------------------------------------------------------------------------
// The browser at the other end of the WebChannel.
// --------------------------------------------------------------------------

const messages = [];

if (job.browser) {
  window.addEventListener('WebChannelMessageToChrome', (event) => {
    const detail = typeof event.detail === 'string' ? JSON.parse(event.detail) : event.detail;
    const { command, data, messageId } = detail.message;
    messages.push({ command, data });

    const reply = job.browser.replies?.[command];
    if (reply === undefined) {
      // Fire-and-forget commands get no answer, exactly as in Firefox.
      return;
    }
    window.dispatchEvent(
      new CustomEvent('WebChannelMessageToContent', {
        detail: JSON.stringify({
          id: 'account_updates',
          message: { command, data: reply, messageId },
        }),
      })
    );
  });
}

// --------------------------------------------------------------------------
// Load the page and drive it.
// --------------------------------------------------------------------------

const settle = (ticks = 40) =>
  new Promise((resolve) => {
    let remaining = ticks;
    const tick = () => (remaining-- > 0 ? setTimeout(tick, 5) : resolve());
    tick();
  });

await import(new URL('app.js', `file://${assetsDir}/`).href);
await settle();

const result = { messages, rendered: root.text, href: window.location.href };

if (job.email) {
  const form = root.find('FORM');
  if (!form) {
    result.error = 'no sign-in form was rendered';
  } else {
    document.getElementById('email').value = job.email;
    document.getElementById('password').value = job.password;
    await form.dispatchEvent({ type: 'submit', preventDefault() {} });
    await settle();
    result.rendered = root.text;
    result.href = window.location.href;
  }
}

process.stdout.write(JSON.stringify(result));
