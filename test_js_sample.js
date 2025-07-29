# test_js_sample.js - Sample file for AI Context Extractor testing

import React, { useEffect, useState } from 'react';

const VulnerableComponent = () => {
  const [userInput, setUserInput] = useState('');
  const [htmlContent, setHtmlContent] = useState('');

  useEffect(() => {
    // VULNERABLE: Direct innerHTML assignment
    document.getElementById('content').innerHTML = userInput;
    
    // VULNERABLE: eval usage  
    eval('console.log("' + userInput + '")');
    
    // VULNERABLE: Function constructor
    new Function('return ' + userInput)();
    
    // VULNERABLE: setTimeout with string
    setTimeout('alert("' + userInput + '")', 1000);
  }, [userInput]);

  // VULNERABLE: dangerouslySetInnerHTML
  const renderContent = () => {
    return <div dangerouslySetInnerHTML={{__html: htmlContent}} />;
  };

  // VULNERABLE: document.write
  const writeToDocument = (data) => {
    document.write('<p>' + data + '</p>');
  };

  return (
    <div>
      <input onChange={(e) => setUserInput(e.target.value)} />
      {renderContent()}
    </div>
  );
};

// VULNERABLE: Web Components
customElements.define('unsafe-element', class extends HTMLElement {
  connectedCallback() {
    this.attachShadow({mode: 'open'});
    // VULNERABLE: Shadow DOM innerHTML
    this.shadowRoot.innerHTML = this.getAttribute('content');
  }
});

// VULNERABLE: JSONP callback
window.jsonpCallback = function(response) {
  // VULNERABLE: eval in JSONP
  eval('processData(' + JSON.stringify(response) + ')');
};

// VULNERABLE: postMessage handler
window.addEventListener('message', function(event) {
  // VULNERABLE: No origin validation + innerHTML
  document.body.innerHTML = event.data;
});

// VULNERABLE: Service Worker
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').then(function(registration) {
    // VULNERABLE: postMessage to SW
    registration.active.postMessage(untrustedData);
  });
}

// VULNERABLE: Template literal injection
const createTemplate = (userContent) => {
  return `<div>${userContent}</div>`;
};

// VULNERABLE: insertAdjacentHTML
const insertUnsafeHTML = (html) => {
  document.body.insertAdjacentHTML('beforeend', html);
};

export default VulnerableComponent;
