import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { User, Send, CheckCircle2, Cpu, SlidersHorizontal, Sparkles, Crosshair, Shield } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type Message = {
  id: string;
  sender: 'ai' | 'user';
  text: string;
  options?: string[];
  extractedData?: Partial<MissionSummary>;
};

type MissionSummary = {
  targetType: string | null;
  scope: string | null;
  depth: string | null;
  safety: string | null;
};

export default function Intake() {
  const [mode, setMode] = useState<'conversational' | 'wizard'>('conversational');
  const [isTyping, setIsTyping] = useState(false);
  const [inputValue, setInputValue] = useState('');

  const [mission, setMission] = useState<MissionSummary>({
    targetType: null,
    scope: null,
    depth: null,
    safety: null,
  });

  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      sender: 'ai',
      text: 'Initiating intake protocol. What environment are we testing today?',
      options: ['External Web App', 'Internal LAN', 'Active Directory', 'Cloud Infrastructure'],
    }
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isTyping]);

  const handleSend = (text: string) => {
    if (!text.trim()) return;

    // Add user message
    const userMsg: Message = { id: Date.now().toString(), sender: 'user', text };
    setMessages(prev => [...prev, userMsg]);
    setInputValue('');
    setIsTyping(true);

    // Simulate AI processing & extraction (Wow effect trigger)
    setTimeout(() => {
      let aiResponse = '';
      let extracted: Partial<MissionSummary> = {};
      let nextOptions: string[] | undefined = undefined;

      if (!mission.targetType) {
        extracted = { targetType: text };
        aiResponse = `Understood. Target type locked as **${text}**. What are the specific IP ranges, CIDRs, or URLs in scope?`;
      } else if (!mission.scope) {
        extracted = { scope: text };
        aiResponse = `Scope mapped to **${text}**. How deep should we go?`;
        nextOptions = ['Passive Only', 'Active Discovery', 'Intrusive Exploitation'];
      } else if (!mission.depth) {
        extracted = { depth: text };
        aiResponse = `Execution depth set to **${text}**. What is our safety posture?`;
        nextOptions = ['Conservative (Safe)', 'Aggressive (Loud)'];
      } else {
        extracted = { safety: text };
        aiResponse = `Safety posture locked to **${text}**. Mission profile is fully mapped and ready for confirmation.`;
      }

      // Update Mission Summary
      if (Object.keys(extracted).length > 0) {
        setMission(prev => ({ ...prev, ...extracted }));
      }

      setMessages(prev => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          sender: 'ai',
          text: aiResponse,
          options: nextOptions,
          extractedData: extracted,
        }
      ]);
      setIsTyping(false);
    }, 1500); // Artificial delay to make it feel like it's "thinking"
  };

  return (
    <div className="flex h-full w-full gap-6">
      {/* LEFT COLUMN: Interaction Area */}
      <div className="flex flex-col flex-1 max-w-3xl h-full border border-border bg-[rgba(12,21,36,0.4)] backdrop-blur-md rounded-xl overflow-hidden shadow-2xl relative">

        {/* Header Toggle */}
        <div className="flex items-center justify-between p-4 border-b border-border bg-[rgba(5,9,18,0.6)]">
          <div className="flex gap-2">
            <button
              onClick={() => setMode('conversational')}
              className={cn("px-4 py-1.5 rounded-full text-xs font-bold transition-all flex items-center gap-2", mode === 'conversational' ? "bg-cyan/10 text-cyan border border-cyan/30" : "text-muted hover:text-text")}
            >
              <Sparkles size={14} />
              AI Intake
            </button>
            <button
              onClick={() => setMode('wizard')}
              className={cn("px-4 py-1.5 rounded-full text-xs font-bold transition-all flex items-center gap-2", mode === 'wizard' ? "bg-cyan/10 text-cyan border border-cyan/30" : "text-muted hover:text-text")}
            >
              <SlidersHorizontal size={14} />
              Manual Wizard
            </button>
          </div>
          <span className="text-[11px] font-mono text-cyan/70 uppercase tracking-widest flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse"></span>
            Aegis Intelligence
          </span>
        </div>

        {/* Content Area */}
        {mode === 'conversational' ? (
          <>
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <AnimatePresence initial={false}>
                {messages.map((msg) => (
                  <motion.div
                    key={msg.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={cn("flex flex-col max-w-[85%]", msg.sender === 'user' ? "ml-auto items-end" : "mr-auto items-start")}
                  >
                    <div className={cn("flex items-end gap-3", msg.sender === 'user' ? "flex-row-reverse" : "flex-row")}>
                      <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-full border shadow-lg", msg.sender === 'ai' ? "bg-cyan/10 border-cyan/30 text-cyan" : "bg-surface border-border text-text")}>
                        {msg.sender === 'ai' ? <Cpu size={16} /> : <User size={16} />}
                      </div>

                      <div className={cn("px-5 py-3 rounded-2xl text-[14px] leading-relaxed shadow-sm", msg.sender === 'user' ? "bg-surface border border-border text-text rounded-br-sm" : "bg-[rgba(14,165,233,0.05)] border border-[rgba(14,165,233,0.15)] text-cyan rounded-bl-sm")}>
                        {/* Process markdown-like bolding visually */}
                        <div dangerouslySetInnerHTML={{ __html: msg.text.replace(/\*\*(.*?)\*\*/g, '<span class="font-bold text-white drop-shadow-[0_0_5px_rgba(255,255,255,0.5)]">$1</span>') }} />
                      </div>
                    </div>

                    {msg.options && (
                      <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.5 }}
                        className={cn("flex flex-wrap gap-2 mt-3", msg.sender === 'user' ? "justify-end" : "justify-start pl-11")}
                      >
                        {msg.options.map(opt => (
                          <button
                            key={opt}
                            onClick={() => handleSend(opt)}
                            className="px-4 py-1.5 rounded-full text-xs font-semibold bg-surface border border-border text-muted hover:text-cyan hover:border-cyan/50 hover:bg-cyan/5 transition-all shadow-[0_2px_10px_rgba(0,0,0,0.2)]"
                          >
                            {opt}
                          </button>
                        ))}
                      </motion.div>
                    )}
                  </motion.div>
                ))}

                {isTyping && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-end gap-3 mr-auto">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-cyan/10 border border-cyan/30 text-cyan shadow-[0_0_10px_rgba(94,207,255,0.2)]">
                      <Cpu size={16} />
                    </div>
                    <div className="px-5 py-4 rounded-2xl bg-[rgba(14,165,233,0.05)] border border-[rgba(14,165,233,0.15)] rounded-bl-sm flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 bg-cyan rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                      <span className="w-1.5 h-1.5 bg-cyan rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                      <span className="w-1.5 h-1.5 bg-cyan rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
              <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="p-4 bg-[rgba(5,9,18,0.8)] border-t border-border">
              <div className="relative flex items-center">
                <input
                  type="text"
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSend(inputValue)}
                  placeholder="Type a natural language instruction or target..."
                  className="w-full bg-surface border border-border rounded-xl py-3 pl-4 pr-12 text-sm text-text focus:outline-none focus:border-cyan/50 focus:ring-1 focus:ring-cyan/50 transition-all placeholder:text-muted shadow-inner"
                  disabled={isTyping}
                />
                <button
                  onClick={() => handleSend(inputValue)}
                  disabled={!inputValue.trim() || isTyping}
                  className="absolute right-2 p-2 rounded-lg text-cyan hover:bg-cyan/10 disabled:opacity-50 disabled:hover:bg-transparent transition-colors"
                >
                  <Send size={18} />
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted flex-col gap-4">
            <SlidersHorizontal size={48} className="opacity-20" />
            <p>Traditional Wizard mode is available for fallback, but AI is recommended.</p>
          </div>
        )}
      </div>

      {/* RIGHT COLUMN: Live Mission Summary */}
      <div className="w-[340px] shrink-0 h-full">
        <div className="border border-border rounded-xl bg-surface/50 backdrop-blur-md h-full flex flex-col relative overflow-hidden">
          {/* Animated Background Web Line */}
          <div className="absolute -top-[100px] -right-[100px] opacity-10 pointer-events-none">
             <Crosshair size={300} className="text-cyan animate-[spin_60s_linear_infinite]" />
          </div>

          <div className="p-5 border-b border-border bg-[rgba(5,9,18,0.8)] relative z-10">
            <h2 className="text-sm font-bold uppercase tracking-widest text-text">Mission Profile</h2>
            <p className="text-[11px] text-muted mt-1">Live data extraction</p>
          </div>

          <div className="p-5 space-y-4 relative z-10 overflow-y-auto">
            <SummaryCard
              label="Target Type"
              value={mission.targetType}
              icon={<Crosshair size={14} />}
              isLatest={messages[messages.length - 1]?.extractedData?.targetType !== undefined}
            />
            <SummaryCard
              label="Scope & Targets"
              value={mission.scope}
              icon={<Crosshair size={14} />}
              isLatest={messages[messages.length - 1]?.extractedData?.scope !== undefined}
            />
            <SummaryCard
              label="Execution Depth"
              value={mission.depth}
              icon={<Shield size={14} />}
              isLatest={messages[messages.length - 1]?.extractedData?.depth !== undefined}
            />
            <SummaryCard
              label="Safety Posture"
              value={mission.safety}
              icon={<CheckCircle2 size={14} />}
              isLatest={messages[messages.length - 1]?.extractedData?.safety !== undefined}
            />

            {/* Launch Button (Appears when fully mapped) */}
            <AnimatePresence>
              {mission.targetType && mission.scope && mission.depth && mission.safety && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="pt-6"
                >
                  <button className="w-full py-3 rounded-lg bg-cyan text-[#04080f] font-bold text-sm shadow-[0_0_20px_rgba(94,207,255,0.4)] hover:shadow-[0_0_30px_rgba(94,207,255,0.6)] transition-all flex items-center justify-center gap-2">
                    <Sparkles size={16} />
                    Confirm & Launch Mission
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({ label, value, icon, isLatest }: { label: string, value: string | null, icon: React.ReactNode, isLatest: boolean }) {
  return (
    <motion.div
      initial={false}
      animate={{
        borderColor: isLatest ? 'rgba(94,207,255,0.8)' : 'rgba(120,177,212,0.15)',
        boxShadow: isLatest ? '0 0 15px rgba(94,207,255,0.15) inset' : 'none'
      }}
      transition={{ duration: 0.5 }}
      className="p-4 rounded-lg bg-[rgba(5,9,18,0.4)] border border-border relative overflow-hidden"
    >
      {isLatest && (
        <motion.div
          initial={{ left: '-100%' }}
          animate={{ left: '200%' }}
          transition={{ duration: 1.5, ease: "easeInOut" }}
          className="absolute top-0 bottom-0 w-[50px] bg-gradient-to-r from-transparent via-cyan/20 to-transparent skew-x-[-20deg]"
        />
      )}

      <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-muted mb-2">
        {icon}
        {label}
      </div>

      {value ? (
        <motion.div
          initial={{ opacity: 0, y: 5 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-[13px] font-semibold text-text"
        >
          {value}
        </motion.div>
      ) : (
        <div className="text-[13px] text-muted/40 italic">Awaiting input...</div>
      )}
    </motion.div>
  );
}
