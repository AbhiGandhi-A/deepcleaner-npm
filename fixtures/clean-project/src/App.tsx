import React, { useEffect, useState } from 'react';

export function App() {
  const [data, setData] = useState<string>('');

  useEffect(() => {
    fetch('/api/profile')
      .then((res) => res.json())
      .then((json) => {
        const decoded = Buffer.from(json.encodedData || '', 'utf-8').toString();
        setData(decoded);
      })
      .catch(() => setData('Default status'));
  }, []);

  return (
    <div className="container">
      <h1>Clean React App</h1>
      <p>{data}</p>
    </div>
  );
}

