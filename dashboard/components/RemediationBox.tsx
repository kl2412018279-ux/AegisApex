// dashboard/components/RemediationBox.tsx

'use client';



import React, { useState } from 'react';

import { Check, Copy, Terminal } from 'lucide-react';



interface RemediationBoxProps {

  commands: string;

}



export default function RemediationBox({ commands }: RemediationBoxProps) {

  const [copied, setCopied] = useState(false);



  const handleCopy = async () => {

    await navigator.clipboard.writeText(commands);

    setCopied(true);

    setTimeout(() => setCopied(false), 2000);

  };



  return (

    <div className="overflow-hidden rounded-lg border border-ops-border bg-ops-surface2/60">

      <div className="flex items-center justify-between border-b border-ops-border bg-ops-surface px-4 py-2 font-mono text-xs text-ops-muted">

        <div className="flex items-center gap-2">

          <Terminal className="h-3.5 w-3.5 text-ops-accent" />

          <span>Recommended Remediation CLI</span>

        </div>

        <button

          onClick={handleCopy}

          className="flex items-center gap-1 text-ops-muted transition-colors hover:text-ops-text"

        >

          {copied ? (

            <>

              <Check className="h-3.5 w-3.5 text-ops-accent" />

              <span className="text-ops-accent">Copied</span>

            </>

          ) : (

            <>

              <Copy className="h-3.5 w-3.5" />

              <span>Copy Commands</span>

            </>

          )}

        </button>

      </div>

      <pre className="overflow-x-auto p-4 font-mono text-xs text-ops-text selection:bg-ops-accent/30 selection:text-ops-text">

        {commands}

      </pre>

    </div>

  );

}