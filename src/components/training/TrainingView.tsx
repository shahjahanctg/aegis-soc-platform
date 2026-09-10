import React, { useState, useEffect } from 'react';
import { 
  GraduationCap, 
  BookOpen, 
  MailWarning, 
  Award, 
  Play, 
  CheckCircle2, 
  X, 
  HelpCircle, 
  Users, 
  Send, 
  MousePointerClick, 
  AlertTriangle,
  Plus
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { Course, Lesson, PhishingCampaign } from '../../types';
import { api } from '../../services/api';

export const TrainingView: React.FC = () => {
  const [courses, setCourses] = useState<Course[]>([]);
  const [campaigns, setCampaigns] = useState<PhishingCampaign[]>([]);
  const [activeTab, setActiveTab] = useState<'courses' | 'phishing' | 'badges'>('courses');
  const [selectedLesson, setSelectedLesson] = useState<{ course: Course; lesson: Lesson } | null>(null);
  const [quizSelection, setQuizSelection] = useState<number | null>(null);
  const [quizSubmitted, setQuizSubmitted] = useState(false);
  const [showCertificate, setShowCertificate] = useState(false);

  // New Campaign Form Modal
  const [isCampaignModalOpen, setIsCampaignModalOpen] = useState(false);
  const [campaignName, setCampaignName] = useState('');
  const [campaignTemplate, setCampaignTemplate] = useState('Microsoft 365 Password Expiry Alert');
  const [campaignTargets, setCampaignTargets] = useState(150);

  useEffect(() => {
    const load = async () => {
      try {
        const [cData, pData] = await Promise.all([
          api.getCourses(),
          api.getPhishingCampaigns(),
        ]);
        setCourses(cData || []);
        setCampaigns(pData || []);
      } catch (err) {
        console.error(err);
      }
    };
    load();
  }, []);

  const handleSelectLesson = (course: Course, lesson: Lesson) => {
    setSelectedLesson({ course, lesson });
    setQuizSelection(null);
    setQuizSubmitted(false);
  };

  const handleCompleteLesson = async () => {
    if (!selectedLesson) return;
    try {
      await api.completeLesson(selectedLesson.course.id, selectedLesson.lesson.id);
      selectedLesson.lesson.completed = true;

      // Update local state
      setCourses(prev => [...prev]);

      // Trigger celebratory confetti if user completed course
      confetti({
        particleCount: 50,
        spread: 60,
        origin: { y: 0.6 }
      });

      setSelectedLesson(null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleLaunchCampaign = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const newCamp = await api.launchPhishingCampaign({
        name: campaignName || 'Enterprise Security Drill',
        template: campaignTemplate,
        targetCount: campaignTargets,
      });
      setCampaigns(prev => [newCamp, ...prev]);
      setIsCampaignModalOpen(false);
      setCampaignName('');
    } catch (err) {
      console.error(err);
    }
  };

  const totalLessons = courses.reduce((acc, c) => acc + c.lessons.length, 0);
  const completedLessons = courses.reduce((acc, c) => acc + c.lessons.filter(l => l.completed).length, 0);
  const overallProgress = totalLessons > 0 ? Math.round((completedLessons / totalLessons) * 100) : 0;

  return (
    <div className="space-y-4">
      {/* Top Banner & Tab Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div>
          <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide flex items-center gap-2">
            <GraduationCap className="h-5 w-5 text-cyan-400" />
            Security Training Academy &amp; Workforce LMS
          </h2>
          <p className="text-xs text-gray-400">
            Interactive analyst modules, phishing simulations, and gamified skill tracks to harden the human layer.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-gray-800 bg-gray-900 p-0.5 text-xs font-mono">
            <button
              onClick={() => setActiveTab('courses')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeTab === 'courses' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Courses &amp; Labs
            </button>
            <button
              onClick={() => setActiveTab('phishing')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeTab === 'phishing' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Phishing Simulations
            </button>
            <button
              onClick={() => setActiveTab('badges')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeTab === 'badges' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Credentials &amp; Badges
            </button>
          </div>
        </div>
      </div>

      {/* Tab 1: Courses & Interactive Labs */}
      {activeTab === 'courses' && (
        <div className="space-y-4">
          {/* LMS Progress Header */}
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono uppercase text-gray-300 font-bold">
                Curriculum Progress: {completedLessons} / {totalLessons} Modules Completed
              </span>
              <span className="text-xs font-mono text-cyan-400 font-bold">{overallProgress}%</span>
            </div>
            <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 transition-all duration-500"
                style={{ width: `${overallProgress}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {courses.map(course => {
              const compCount = course.lessons.filter(l => l.completed).length;
              const courseProgress = Math.round((compCount / course.lessons.length) * 100);

              return (
                <div
                  key={course.id}
                  className="flex flex-col justify-between rounded-xl border border-gray-800 bg-gray-950 p-5 shadow-lg hover:border-cyan-500/40 transition-all"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-[10px] font-mono text-cyan-300 border border-cyan-800">
                        {course.category}
                      </span>
                      <span className="text-[10px] font-mono text-gray-400 font-semibold">{course.level}</span>
                    </div>

                    <h3 className="font-mono text-sm font-bold text-gray-100">{course.title}</h3>
                    <p className="mt-1 text-xs text-gray-400 line-clamp-2 leading-relaxed">
                      {course.description}
                    </p>
                    <p className="mt-2 text-[11px] font-mono text-gray-500">Instructor: {course.instructor}</p>

                    {/* Lessons list */}
                    <div className="mt-4 space-y-1.5 border-t border-gray-800/80 pt-3">
                      <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider block mb-1">
                        Modules &amp; Labs ({compCount}/{course.lessons.length})
                      </span>
                      {course.lessons.map(lesson => (
                        <div
                          key={lesson.id}
                          onClick={() => handleSelectLesson(course, lesson)}
                          className={`flex items-center justify-between p-2 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                            lesson.completed
                              ? 'bg-emerald-950/30 text-emerald-300 border border-emerald-900/40'
                              : 'bg-gray-900/60 text-gray-300 border border-gray-800/60 hover:bg-gray-800'
                          }`}
                        >
                          <div className="flex items-center gap-2 truncate">
                            {lesson.completed ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                            ) : (
                              <Play className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                            )}
                            <span className="truncate">{lesson.title}</span>
                          </div>
                          <span className="text-[10px] text-gray-500 shrink-0">{lesson.duration}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-gray-800 flex items-center justify-between">
                    <span className="text-xs font-mono text-gray-400">{courseProgress}% Done</span>
                    {courseProgress === 100 && (
                      <button
                        onClick={() => setShowCertificate(true)}
                        className="flex items-center gap-1 text-xs font-mono text-emerald-400 hover:text-emerald-300 cursor-pointer"
                      >
                        <Award className="h-3.5 w-3.5" /> View Certificate
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 2: Phishing Simulation Campaign Manager */}
      {activeTab === 'phishing' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-mono text-sm font-bold text-gray-200 uppercase">
              Active &amp; Historical Phishing Drills
            </h3>
            <button
              onClick={() => setIsCampaignModalOpen(true)}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-gray-950 transition-all cursor-pointer"
            >
              <Plus className="h-4 w-4" />
              Launch New Simulation
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {campaigns.map(camp => {
              const openRate = Math.round((camp.openedCount / camp.sentCount) * 100);
              const clickRate = Math.round((camp.clickedCount / camp.sentCount) * 100);
              const compRate = Math.round((camp.compromisedCount / camp.sentCount) * 100);

              return (
                <div key={camp.id} className="rounded-xl border border-gray-800 bg-gray-950 p-5 shadow-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs text-gray-500">{camp.id}</span>
                    <span className={`rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase border ${
                      camp.status === 'active' ? 'bg-cyan-950 text-cyan-300 border-cyan-800' : 'bg-gray-900 text-gray-400 border-gray-800'
                    }`}>
                      {camp.status}
                    </span>
                  </div>

                  <h4 className="font-mono text-sm font-bold text-gray-100">{camp.name}</h4>
                  <p className="text-xs text-gray-400 font-mono mt-0.5">Template: {camp.template}</p>

                  {/* Funnel Metrics */}
                  <div className="mt-4 grid grid-cols-4 gap-2 text-center font-mono">
                    <div className="rounded-lg bg-gray-900 p-2 border border-gray-800">
                      <span className="text-[10px] text-gray-500 block">Sent</span>
                      <span className="text-sm font-bold text-gray-200">{camp.sentCount}</span>
                    </div>
                    <div className="rounded-lg bg-gray-900 p-2 border border-gray-800">
                      <span className="text-[10px] text-gray-500 block">Opened</span>
                      <span className="text-sm font-bold text-cyan-400">{openRate}%</span>
                    </div>
                    <div className="rounded-lg bg-gray-900 p-2 border border-gray-800">
                      <span className="text-[10px] text-gray-500 block">Clicked</span>
                      <span className="text-sm font-bold text-amber-400">{clickRate}%</span>
                    </div>
                    <div className="rounded-lg bg-gray-900 p-2 border border-rose-900/60 bg-rose-950/20">
                      <span className="text-[10px] text-rose-400 block">Compromised</span>
                      <span className="text-sm font-bold text-rose-400">{compRate}%</span>
                    </div>
                  </div>

                  <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-gray-400">
                    <span>Target Cohort: Employees</span>
                    <span className="text-cyan-400 font-semibold">Auto-Assigned Training for {camp.compromisedCount} users</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 3: Credentials & Badges */}
      {activeTab === 'badges' && (
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-6">
          <h3 className="font-mono text-base font-bold text-gray-100 uppercase mb-4">
            Earned Cybersecurity Badges &amp; Endorsements
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="flex items-center gap-3 rounded-xl border border-cyan-900/50 bg-cyan-950/20 p-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/40">
                <Award className="h-6 w-6" />
              </div>
              <div>
                <h4 className="font-mono text-sm font-bold text-cyan-300">SOC Tier 1 Certified</h4>
                <p className="text-xs text-gray-400">Incident triage &amp; MITRE ATT&amp;CK analysis</p>
              </div>
            </div>

            <div className="flex items-center gap-3 rounded-xl border border-purple-900/50 bg-purple-950/20 p-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-purple-500/20 text-purple-400 border border-purple-500/40">
                <Award className="h-6 w-6" />
              </div>
              <div>
                <h4 className="font-mono text-sm font-bold text-purple-300">DFIR Memory Hunter</h4>
                <p className="text-xs text-gray-400">Volatility 3 &amp; malware injection detection</p>
              </div>
            </div>

            <div className="flex items-center gap-3 rounded-xl border border-amber-900/50 bg-amber-950/20 p-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/40">
                <Award className="h-6 w-6" />
              </div>
              <div>
                <h4 className="font-mono text-sm font-bold text-amber-300">Anti-Phishing Sentinel</h4>
                <p className="text-xs text-gray-400">Header forensics &amp; AiTM mitigation</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Lesson Modal */}
      {selectedLesson && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-2xl rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl">
            <button
              onClick={() => setSelectedLesson(null)}
              className="absolute right-4 top-4 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 hover:text-gray-100 cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>

            <span className="font-mono text-xs text-cyan-400 uppercase">
              {selectedLesson.course.title} &bull; {selectedLesson.lesson.duration}
            </span>
            <h3 className="mt-1 text-lg font-bold text-gray-100 font-mono">
              {selectedLesson.lesson.title}
            </h3>

            <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900/60 p-4 text-xs text-gray-300 leading-relaxed font-sans">
              <h4 className="text-cyan-400 font-mono font-bold mb-2 uppercase">Scenario &amp; Theory</h4>
              <p>{selectedLesson.lesson.content}</p>
            </div>

            {/* Quiz section */}
            {selectedLesson.lesson.quiz && (
              <div className="mt-4 rounded-xl border border-purple-900/40 bg-purple-950/20 p-4">
                <h4 className="flex items-center gap-1.5 text-xs font-mono font-bold text-purple-300 uppercase mb-3">
                  <HelpCircle className="h-4 w-4 text-purple-400" />
                  Knowledge Check Quiz
                </h4>
                <p className="text-xs font-mono text-gray-200 mb-3 font-semibold">
                  {selectedLesson.lesson.quiz.question}
                </p>

                <div className="space-y-2">
                  {selectedLesson.lesson.quiz.options.map((opt, idx) => {
                    const isCorrect = idx === selectedLesson.lesson.quiz!.correctIndex;
                    const isChosen = quizSelection === idx;

                    return (
                      <button
                        key={idx}
                        onClick={() => !quizSubmitted && setQuizSelection(idx)}
                        className={`w-full text-left rounded-lg p-2.5 text-xs font-mono transition-all cursor-pointer border ${
                          quizSubmitted
                            ? isCorrect
                              ? 'bg-emerald-950/80 border-emerald-700 text-emerald-300 font-bold'
                              : isChosen
                              ? 'bg-rose-950/80 border-rose-700 text-rose-300'
                              : 'bg-gray-900/40 border-gray-800 text-gray-500'
                            : isChosen
                            ? 'bg-cyan-950 border-cyan-600 text-cyan-200'
                            : 'bg-gray-900 border-gray-800 text-gray-300 hover:bg-gray-850'
                        }`}
                      >
                        {opt}
                      </button>
                    );
                  })}
                </div>

                {!quizSubmitted ? (
                  <button
                    disabled={quizSelection === null}
                    onClick={() => setQuizSubmitted(true)}
                    className="mt-3 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-50 px-3 py-1.5 text-xs font-mono text-white transition-all cursor-pointer"
                  >
                    Submit Answer
                  </button>
                ) : (
                  <div className="mt-3 text-xs font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800 p-2.5 rounded-lg">
                    <strong>Explanation:</strong> {selectedLesson.lesson.quiz.explanation}
                  </div>
                )}
              </div>
            )}

            <div className="mt-6 flex items-center justify-end gap-3 border-t border-gray-800 pt-4">
              <button
                onClick={() => setSelectedLesson(null)}
                className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-2 text-xs font-mono text-gray-400 hover:bg-gray-800 cursor-pointer"
              >
                Close
              </button>
              <button
                onClick={handleCompleteLesson}
                className="flex items-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-xs font-semibold text-gray-950 transition-all shadow-[0_0_15px_rgba(16,185,129,0.3)] cursor-pointer"
              >
                <CheckCircle2 className="h-4 w-4" />
                Mark Module Completed
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Certificate Modal */}
      {showCertificate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-xl rounded-2xl border-2 border-amber-500/60 bg-gray-950 p-8 text-center shadow-[0_0_50px_rgba(245,158,11,0.2)]">
            <button
              onClick={() => setShowCertificate(false)}
              className="absolute right-4 top-4 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 hover:text-gray-100 cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>

            <Award className="mx-auto h-16 w-16 text-amber-400 animate-bounce" />
            <span className="mt-2 block font-mono text-xs text-amber-400 uppercase tracking-widest">
              CERTIFICATE OF COMPLETION
            </span>
            <h2 className="mt-2 text-xl font-bold font-mono text-gray-100">
              CYBER DEFENSE OPERATIONS SPECIALIST
            </h2>
            <p className="mt-2 text-xs text-gray-400">
              Awarded for mastering incident triage, host containment, memory forensics, and MITRE ATT&amp;CK framework defense.
            </p>
            <div className="mt-6 border-t border-gray-800 pt-4 flex justify-between text-[11px] font-mono text-gray-500">
              <span>ISSUED BY: AEGIS SOC TRAINING ACADEMY</span>
              <span>VERIFICATION ID: #CERT-2026-901</span>
            </div>
          </div>
        </div>
      )}

      {/* Launch Phishing Simulation Modal */}
      {isCampaignModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-md rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl font-mono text-xs">
            <button
              onClick={() => setIsCampaignModalOpen(false)}
              className="absolute right-4 top-4 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>

            <h3 className="text-base font-bold text-gray-100 uppercase mb-4">
              Launch Phishing Awareness Simulation
            </h3>

            <form onSubmit={handleLaunchCampaign} className="space-y-3">
              <div>
                <label className="block text-gray-400 mb-1">Drill Name</label>
                <input
                  type="text"
                  required
                  value={campaignName}
                  onChange={(e) => setCampaignName(e.target.value)}
                  placeholder="e.g. Q1 IT Compliance Drill"
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1">Email Lure Template</label>
                <select
                  value={campaignTemplate}
                  onChange={(e) => setCampaignTemplate(e.target.value)}
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-200 focus:border-cyan-500 focus:outline-none"
                >
                  <option value="Microsoft 365 Password Expiry Alert">Microsoft 365 Password Expiry Alert</option>
                  <option value="CFO Urgent Wire Authorization">CFO Urgent Wire Authorization</option>
                  <option value="HR Mandatory Benefits Enrollment">HR Mandatory Benefits Enrollment</option>
                  <option value="DocuSign Contract Signature Request">DocuSign Contract Signature Request</option>
                </select>
              </div>

              <div>
                <label className="block text-gray-400 mb-1">Target Recipient Count</label>
                <input
                  type="number"
                  min="10"
                  max="1000"
                  value={campaignTargets}
                  onChange={(e) => setCampaignTargets(Number(e.target.value))}
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsCampaignModalOpen(false)}
                  className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-gray-400 hover:bg-gray-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-cyan-600 hover:bg-cyan-500 px-4 py-1.5 font-semibold text-gray-950 cursor-pointer"
                >
                  Launch Campaign
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
