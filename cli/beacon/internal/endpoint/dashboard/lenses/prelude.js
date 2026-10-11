// Lens frame prelude. The dashboard injects this ahead of every lens, so it runs before any lens
// code. It defines window.beacon and owns the frame's half of the host protocol:
//
//   host -> window   one postMessage {type: "beacon.lens.connect", version: 1} carrying a
//                    MessagePort, and nothing else.
//   frame -> port    {type: "getTrace"}            the lens asked for its data
//                    {type: "resize", height: n}   document height changed
//                    {type: "error", message: s}   uncaught error or unhandled rejection
//   port -> frame    {type: "trace", data: {...}}  the LensDataV1
//                    {type: "traceError", message: s}
//
// Trace data only ever crosses the private port. Everything that arrives here is checked, because
// the host is the only party allowed to talk to the frame and anything else is ignored.
(function () {
  "use strict";

  // Everything from here to the host protocol is best-effort hardening, not a boundary. The CSP and
  // the sandbox are what the browser enforces; they keep a lens away from Beacon and the dashboard
  // and refuse the ordinary network APIs. They do not govern WebRTC or every resource hint, and no
  // CSP or Permissions Policy directive does, so a lens is code trusted with the trace it is shown.
  // These guards close the common paths to those features; a determined lens can find others.

  // WebRTC: connect-src does not apply to ICE, so a lens could hand trace data to a STUN/TURN server
  // it names. Remove every RTC* interface (and the webkit alias) from this realm as non-configurable,
  // non-writable undefined properties, so lens code can neither delete nor redefine them. A frame
  // the lens creates is a fresh realm where they still exist: the parent cannot reach into it (a
  // sandboxed child has its own opaque origin), but a srcdoc child runs its own scripts. The
  // document guard below refuses such frames.
  Object.getOwnPropertyNames(window).forEach(function (name) {
    if (!/^(webkit)?RTC/.test(name)) return;
    try {
      Object.defineProperty(window, name, { value: undefined, writable: false, configurable: false, enumerable: false });
    } catch (e) {
      // A property that is already non-configurable cannot be replaced; leave it.
    }
  });

  // Document guard. A lens may not put into its document a nested browsing context (iframe, frame,
  // object, embed, portal, fencedframe: a fresh realm with WebRTC intact), a <link> (a lens loads
  // nothing by URL, and rel=preconnect/prefetch/prerender/dns-prefetch/preload can start a request
  // the CSP does not see), or a <script type=speculationrules>. Creating, inserting or parsing one
  // in through the DOM APIs throws (markup is parsed in the real call's document and context, so
  // the check sees what the browser builds); document.write and execCommand("insertHTML") are
  // refused outright; a mutation observer removes any that the parser puts in from the lens file's
  // own markup. Not covered: what the browser's
  // preload scanner does with the file's own markup before any script runs, closed declarative
  // shadow roots, and attribute changes made through Attr nodes. `beacon lenses lint` warns on these
  // elements and on declarative shadow roots in source. Everything the guard calls is captured
  // here, before lens code can patch it.
  (function guardDocument() {
    var apply = Reflect.apply;
    var Refusal = DOMException;
    var HTML_NS = "http://www.w3.org/1999/xhtml";
    var REFUSED = Object.create(null);
    ["iframe", "frame", "frameset", "object", "embed", "portal", "fencedframe", "link"].forEach(function (name) {
      REFUSED[name] = true;
    });
    var SELECTOR = "iframe,frame,frameset,object,embed,portal,fencedframe,link,script,template";

    function getter(proto, name) {
      var get = Object.getOwnPropertyDescriptor(proto, name).get;
      return function (target) { return apply(get, target, []); };
    }
    function method(proto, name) {
      var fn = proto[name];
      return function (target, args) { return apply(fn, target, args); };
    }
    var nodeType = getter(Node.prototype, "nodeType");
    var localName = getter(Element.prototype, "localName");
    var namespaceURI = getter(Element.prototype, "namespaceURI");
    var templateContent = getter(HTMLTemplateElement.prototype, "content");
    var shadowRoot = getter(Element.prototype, "shadowRoot");
    var listLength = getter(NodeList.prototype, "length");
    var addedNodes = getter(MutationRecord.prototype, "addedNodes");
    var ownerDocument = getter(Node.prototype, "ownerDocument");
    var parentNode = getter(Node.prototype, "parentNode");
    var childNodes = getter(Node.prototype, "childNodes");
    var shadowHost = getter(ShadowRoot.prototype, "host");
    var createElementNS = method(Document.prototype, "createElementNS");
    var setInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML").set;
    var indexOf = method(String.prototype, "indexOf");
    // The native insertions, kept before they are wrapped below.
    var insert = Object.create(null);
    ["replaceChildren", "replaceWith", "before", "after", "prepend", "append"].forEach(function (name) {
      insert[name] = method(Element.prototype, name);
    });
    insert.fragmentReplaceChildren = method(DocumentFragment.prototype, "replaceChildren");
    var getAttribute = method(Element.prototype, "getAttribute");
    var removeElement = method(Element.prototype, "remove");
    var trim = method(String.prototype, "trim");
    var lower = method(String.prototype, "toLowerCase");
    var parseHTML = method(DOMParser.prototype, "parseFromString");
    var parser = new DOMParser();
    var queryAll = Object.create(null);
    queryAll[1] = method(Element.prototype, "querySelectorAll");
    queryAll[9] = method(Document.prototype, "querySelectorAll");
    queryAll[11] = method(DocumentFragment.prototype, "querySelectorAll");

    function refuse(what) {
      throw new Refusal("a Beacon lens cannot " + what, "NotSupportedError");
    }
    // Strings are converted once, here, so a value whose toString changes between calls cannot show
    // the check one string and the browser another. nullToEmpty matches innerHTML and outerHTML.
    function text(value) {
      return typeof value === "string" ? value : "" + value;
    }
    function nullToEmpty(value) {
      return value === null ? "" : text(value);
    }
    function isSpeculationRules(type) {
      return type !== null && lower(trim(text(type), []), []) === "speculationrules";
    }
    function isRefused(el) {
      if (namespaceURI(el) !== HTML_NS) return false;
      var name = localName(el);
      return REFUSED[name] === true || (name === "script" && isSpeculationRules(getAttribute(el, ["type"])));
    }
    // Calls found(el) for every refused element in node and its subtree, template contents and open
    // shadow roots included.
    function eachRefused(node, found) {
      var type;
      try {
        type = nodeType(node);
      } catch (e) {
        return; // not a node
      }
      if (type === 1) {
        if (isRefused(node)) return found(node);
        if (namespaceURI(node) === HTML_NS && localName(node) === "template") eachRefused(templateContent(node), found);
        var root = shadowRoot(node);
        if (root) eachRefused(root, found);
      }
      if (!queryAll[type]) return;
      var list = queryAll[type](node, [SELECTOR]);
      for (var i = 0, n = listLength(list); i < n; i++) eachRefused(list[i], found);
    }
    function checkNode(node) {
      eachRefused(node, function (el) { refuse("add a <" + localName(el) + "> element"); });
    }
    // Parses markup as the browser does for the fragment parsing behind innerHTML and its kin: in the
    // same document (so with the same scripting flag, which decides whether <noscript> is raw text)
    // and with a context element of the same name and namespace (which decides how <svg>, <math>,
    // tables and raw-text elements read it). The scratch context is detached, so nothing parsed into
    // it loads. Returns the parsed nodes once none of them, template contents included, is refused;
    // the caller inserts exactly these nodes, so the browser never parses the markup a second time.
    function parseInContext(context, markup) {
      var ns = namespaceURI(context);
      var name = localName(context);
      // An autonomous custom element parses like any unknown element; do not run its constructor.
      if (ns === HTML_NS && indexOf(name, ["-"]) >= 0) name = "div";
      var scratch = createElementNS(ownerDocument(context), [ns, name]);
      apply(setInnerHTML, scratch, [markup]);
      var root = ns === HTML_NS && name === "template" ? templateContent(scratch) : scratch;
      var list = childNodes(root);
      var nodes = Object.create(null);
      nodes.length = listLength(list);
      for (var i = 0; i < nodes.length; i++) nodes[i] = list[i];
      for (var j = 0; j < nodes.length; j++) checkNode(nodes[j]);
      return nodes;
    }
    // The context the browser uses for markup inserted beside or into node: a shadow root parses in
    // its host's context, and a fragment or an <html> element in a new <body>'s.
    function contextFor(node) {
      var type = nodeType(node);
      if (type === 11 && isShadowRoot(node)) return shadowHost(node);
      if (type === 1 && !(namespaceURI(node) === HTML_NS && localName(node) === "html")) return node;
      return createElementNS(ownerDocument(node), [HTML_NS, "body"]);
    }
    function isShadowRoot(node) {
      try {
        shadowHost(node);
        return true;
      } catch (e) {
        return false;
      }
    }
    // A whole document parsed with no browsing context (Document.parseHTMLUnsafe) parses like a
    // DOMParser document: scripting off, no context element.
    function checkDocumentMarkup(markup) {
      checkNode(parseHTML(parser, [markup, "text/html"]));
    }

    function wrapMethod(proto, name, check) {
      var original = proto && proto[name];
      if (typeof original !== "function") return;
      proto[name] = function () {
        check(this, arguments);
        return apply(original, this, arguments);
      };
    }
    // handle(target, value, set) replaces the setter; set(target, value) is the native one.
    function wrapSetter(proto, name, handle, convert) {
      var desc = proto && Object.getOwnPropertyDescriptor(proto, name);
      if (!desc || !desc.set) return;
      var native = desc.set;
      function set(target, value) {
        apply(native, target, [value]);
      }
      Object.defineProperty(proto, name, {
        get: desc.get,
        set: function (value) {
          handle(this, (convert || text)(value), set);
        },
        enumerable: desc.enumerable,
        configurable: true
      });
    }
    function checkNodeArgs(target, args) {
      for (var i = 0; i < args.length; i++) checkNode(args[i]);
    }

    // Creation and insertion. A refused element is refused when it is created, whatever its case or
    // prefix, and again whenever it would enter a tree.
    ["createElement", "createElementNS"].forEach(function (name) {
      var create = Document.prototype[name];
      Document.prototype[name] = function () {
        var el = apply(create, this, arguments);
        checkNode(el);
        return el;
      };
    });
    ["appendChild", "insertBefore", "replaceChild"].forEach(function (name) {
      wrapMethod(Node.prototype, name, checkNodeArgs);
    });
    [Element, Document, DocumentFragment, CharacterData, DocumentType].forEach(function (type) {
      ["append", "prepend", "replaceChildren", "before", "after", "replaceWith", "moveBefore", "insertAdjacentElement"].forEach(function (name) {
        if (Object.prototype.hasOwnProperty.call(type.prototype, name)) wrapMethod(type.prototype, name, checkNodeArgs);
      });
    });
    wrapMethod(Range.prototype, "insertNode", checkNodeArgs);
    wrapMethod(Range.prototype, "surroundContents", checkNodeArgs);

    // HTML parsing into a document. innerHTML, outerHTML and insertAdjacentHTML parse the markup once,
    // in the real context, check the result and insert exactly those nodes (parseInContext).
    function setInner(target, markup) {
      var nodes = parseInContext(contextFor(target), markup);
      if (nodeType(target) === 11) {
        insert.fragmentReplaceChildren(target, nodes);
      } else if (namespaceURI(target) === HTML_NS && localName(target) === "template") {
        insert.fragmentReplaceChildren(templateContent(target), nodes);
      } else {
        insert.replaceChildren(target, nodes);
      }
    }
    wrapSetter(Element.prototype, "innerHTML", setInner, nullToEmpty);
    wrapSetter(ShadowRoot.prototype, "innerHTML", setInner, nullToEmpty);
    wrapSetter(Element.prototype, "outerHTML", function (target, markup, set) {
      var parent = parentNode(target);
      // No parent: the native setter does nothing. A document parent: it throws before parsing.
      if (parent === null || nodeType(parent) === 9) return set(target, markup);
      insert.replaceWith(target, parseInContext(contextFor(parent), markup));
    }, nullToEmpty);
    var insertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (position, markup) {
      var where = lower(text(position), []);
      var outside = where === "beforebegin" || where === "afterend";
      var parent = outside ? parentNode(this) : this;
      if ((!outside && where !== "afterbegin" && where !== "beforeend") || parent === null || nodeType(parent) === 9) {
        return apply(insertAdjacentHTML, this, arguments); // the native call throws (or does nothing)
      }
      var nodes = parseInContext(contextFor(parent), text(markup));
      var into = { beforebegin: insert.before, afterbegin: insert.prepend, beforeend: insert.append, afterend: insert.after };
      into[where](this, nodes);
    };
    // setHTMLUnsafe and setHTML also build declarative shadow roots, which parseInContext's nodes
    // cannot carry, so they are checked in the real context (a closed root's content is checked as
    // the template it is written in) and then handed to the native parser with the same string. As
    // a second line, anything refused that the native parse still produced, where a scan can see it,
    // is removed before the call returns.
    [Element, ShadowRoot].forEach(function (type) {
      ["setHTMLUnsafe", "setHTML"].forEach(function (name) {
        var native = type.prototype[name];
        if (typeof native !== "function") return;
        type.prototype[name] = function (markup) {
          var args = arguments;
          args[0] = text(markup);
          parseInContext(contextFor(this), args[0]);
          var result = apply(native, this, args);
          var removed = false;
          eachRefused(this, function (el) { removeElement(el, []); removed = true; });
          if (removed) refuse("add a nested frame, a <link> or speculation rules");
          return result;
        };
      });
    });
    if (typeof Document.parseHTMLUnsafe === "function") {
      var parseHTMLUnsafe = Document.parseHTMLUnsafe;
      Document.parseHTMLUnsafe = function (markup) {
        var converted = text(markup);
        checkDocumentMarkup(converted);
        return apply(parseHTMLUnsafe, this, [converted]);
      };
    }
    // insertHTML parses in whatever context the selection is in; a lens has no use for it.
    wrapMethod(Document.prototype, "execCommand", function (doc, args) {
      if (lower(text(args[0]), []) === "inserthtml") refuse("use execCommand(\"insertHTML\")");
    });
    // document.write can split one element across calls, so no single call can be checked.
    ["write", "writeln"].forEach(function (name) {
      wrapMethod(Document.prototype, name, function () { refuse("use document." + name); });
    });

    // A frame that is somehow detached and kept cannot be given a document, and a script cannot
    // become speculation rules after it was created.
    [[HTMLIFrameElement, "srcdoc"], [HTMLIFrameElement, "src"], [HTMLFrameElement, "src"], [HTMLObjectElement, "data"], [HTMLEmbedElement, "src"]]
      .forEach(function (entry) {
        wrapSetter(entry[0].prototype, entry[1], function () { refuse("load a nested frame"); });
      });
    wrapSetter(HTMLScriptElement.prototype, "type", function (el, type, set) {
      if (isSpeculationRules(type)) refuse("add speculation rules");
      set(el, type);
    });
    function checkScriptType(el, name, value) {
      if (lower(text(name), []) === "type" && namespaceURI(el) === HTML_NS && localName(el) === "script" && isSpeculationRules(value)) {
        refuse("add speculation rules");
      }
    }
    wrapMethod(Element.prototype, "setAttribute", function (el, args) {
      args[1] = text(args[1]);
      checkScriptType(el, args[0], args[1]);
    });
    wrapMethod(Element.prototype, "setAttributeNS", function (el, args) {
      args[2] = text(args[2]);
      if (args[0] === null || args[0] === undefined || args[0] === "") checkScriptType(el, args[1], args[2]);
    });

    // The lens file's own markup reaches the document through the parser, which calls none of the
    // above. Remove what it inserts at the next microtask checkpoint: before the next script runs
    // and before a frame's document loads.
    var Observer = MutationObserver;
    var observe = method(Observer.prototype, "observe");
    var options = Object.create(null);
    options.childList = true;
    options.subtree = true;
    var observer = new Observer(function (records) {
      for (var i = 0; i < records.length; i++) {
        var nodes = addedNodes(records[i]);
        for (var j = 0, n = listLength(nodes); j < n; j++) {
          eachRefused(nodes[j], function (el) { removeElement(el, []); });
          if (nodeType(nodes[j]) === 1 && shadowRoot(nodes[j])) observe(observer, [shadowRoot(nodes[j]), options]);
        }
      }
    });
    observe(observer, [document, options]);
  })();

  var TIMEOUT_MS = 10000;
  var port = null;
  var pending = [];
  var tracePromise = null;
  var settle = null;

  function send(message) {
    if (port) {
      port.postMessage(message);
    } else {
      pending.push(message);
    }
  }

  function onPortMessage(event) {
    var message = event.data;
    if (!message || typeof message !== "object" || !settle) return;
    if (message.type === "trace") {
      settle(null, message.data);
    } else if (message.type === "traceError") {
      settle(new Error(String(message.message || "the dashboard could not load this trace")));
    }
  }

  // Registered first and in the capture phase, so this listener sees the connect message before any
  // lens listener can, and stops it there: the port is the frame's only channel to the host.
  window.addEventListener("message", function onConnect(event) {
    var message = event.data;
    if (event.source !== window.parent || !message || message.type !== "beacon.lens.connect" || !event.ports || !event.ports[0]) {
      return;
    }
    event.stopImmediatePropagation();
    window.removeEventListener("message", onConnect, true);
    port = event.ports[0];
    port.onmessage = onPortMessage;
    while (pending.length) port.postMessage(pending.shift());
  }, true);

  function getTrace() {
    if (!tracePromise) {
      tracePromise = new Promise(function (resolve, reject) {
        var timer = setTimeout(function () {
          settle(new Error("the dashboard did not send this trace within " + TIMEOUT_MS / 1000 + " seconds"));
        }, TIMEOUT_MS);
        settle = function (err, data) {
          clearTimeout(timer);
          settle = null;
          if (err) {
            reject(err);
          } else {
            resolve(data);
          }
        };
      });
      send({ type: "getTrace" });
    }
    return tracePromise;
  }

  Object.defineProperty(window, "beacon", {
    value: Object.freeze({ getTrace: getTrace }),
    writable: false,
    configurable: false,
    enumerable: true
  });

  // The host sizes the frame to its content. Report the document height whenever it changes.
  var lastHeight = -1;
  function reportHeight() {
    var root = document.documentElement;
    var height = Math.ceil(Math.max(root ? root.scrollHeight : 0, document.body ? document.body.scrollHeight : 0));
    if (height !== lastHeight) {
      lastHeight = height;
      send({ type: "resize", height: height });
    }
  }
  function observeSize() {
    if (typeof ResizeObserver === "function") {
      new ResizeObserver(reportHeight).observe(document.documentElement);
    }
    reportHeight();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", observeSize);
  } else {
    observeSize();
  }

  function reportError(message) {
    send({ type: "error", message: String(message).slice(0, 500) });
  }
  window.addEventListener("error", function (event) {
    reportError(event.message || "error");
  });
  window.addEventListener("unhandledrejection", function (event) {
    var reason = event.reason;
    reportError((reason && reason.message) || reason || "unhandled rejection");
  });
})();
