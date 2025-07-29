// Demo React component with multiple XSS vulnerabilities for AI tools demonstration
import React, { useEffect, useState } from "react";

function VulnerableComponent({ userInput, userCode, dangerousContent }) {
  const [data, setData] = useState("");
  const [config, setConfig] = useState({});

  // CRITICAL: eval in useEffect - AI Context Extractor should detect this
  useEffect(() => {
    eval(userInput); // High-risk pattern
    setData(userCode);
  }, [userInput]);

  // CRITICAL: dangerouslySetInnerHTML - React-specific vulnerability
  const renderUserContent = () => {
    return { __html: dangerousContent };
  };

  // HIGH: Shadow DOM manipulation
  useEffect(() => {
    const element = document.getElementById("shadow-container");
    if (element && element.shadowRoot) {
      element.shadowRoot.innerHTML = userInput; // DOM sink
    }
  }, [userInput]);

  // MEDIUM: innerHTML sink
  const updateContent = (content) => {
    document.getElementById("user-content").innerHTML = content;
  };

  // HIGH: Dynamic function creation
  const executeUserFunction = (funcCode) => {
    const userFunc = new Function(funcCode);
    return userFunc();
  };

  // MEDIUM: setAttribute with user input
  const setUserAttribute = (element, value) => {
    element.setAttribute("data-user", value);
  };

  return (
    <div>
      <h1>Vulnerable React Component</h1>

      {/* CRITICAL: dangerouslySetInnerHTML */}
      <div dangerouslySetInnerHTML={renderUserContent()} />

      {/* DOM containers for manipulation */}
      <div id="user-content"></div>
      <div id="shadow-container"></div>

      {/* Event handlers with user input */}
      <button onClick={() => eval(userCode)}>Execute User Code</button>
      <button onClick={() => executeUserFunction(userInput)}>
        Run Function
      </button>

      {/* Template rendering */}
      <div>{userInput}</div>
    </div>
  );
}

export default VulnerableComponent;
