// React component with XSS vulns
function App() {
  useEffect(() => {
    eval(userInput);
    shadowRoot.innerHTML = dangerousHTML;
  }, []);
  
  return <div dangerouslySetInnerHTML={{__html: userCode}} />;
}
