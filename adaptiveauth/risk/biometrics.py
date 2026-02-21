"""
AdaptiveAuth Behavioral Biometrics
Detects if user is human or bot based on typing patterns, mouse movements, and touch behavior.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import deque
import statistics


@dataclass
class TypingPattern:
    """Stores typing behavior metrics."""
    keystrokes: List[Dict[str, Any]] = field(default_factory=list)
    backspace_count: int = 0
    typo_corrections: int = 0
    avg_typing_speed: float = 0.0  # chars per minute
    consistency_score: float = 0.0  # 0-100
    human_likelihood: float = 0.0  # 0-100


@dataclass
class MousePattern:
    """Stores mouse behavior metrics."""
    movements: List[Dict[str, Any]] = field(default_factory=list)
    clicks: List[Dict[str, Any]] = field(default_factory=list)
    avg_speed: float = 0.0
    path_curvature: float = 0.0  # how curved the path is (humans have curved paths)
    hesitation_score: float = 0.0  # pauses before clicks
    human_likelihood: float = 0.0


@dataclass
class TouchPattern:
    """Stores touch behavior metrics for mobile."""
    gestures: List[Dict[str, Any]] = field(default_factory=list)
    pressure_variance: float = 0.0
    swipe_curvature: float = 0.0
    human_likelihood: float = 0.0


@dataclass
class BehaviorProfile:
    """Complete behavioral profile for a session."""
    session_id: str
    typing: TypingPattern = field(default_factory=TypingPattern)
    mouse: MousePattern = field(default_factory=MousePattern)
    touch: TouchPattern = field(default_factory=TouchPattern)
    overall_human_score: float = 50.0  # 0-100, default neutral
    bot_indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0
    last_updated: datetime = field(default_factory=datetime.utcnow)


class BehavioralBiometrics:
    """
    Analyzes user behavior to detect bots vs humans.
    Runs in background and continuously updates risk scores.
    """
    
    # Human behavior thresholds
    HUMAN_TYPING_SPEED_MIN = 20  # chars per minute (slow typist)
    HUMAN_TYPING_SPEED_MAX = 600  # chars per minute (fast typist)
    BOT_TYPING_SPEED_THRESHOLD = 1000  # bots type very fast
    
    # Consistency thresholds
    HUMAN_VARIABILITY_MIN = 15  # humans have natural variation
    HUMAN_VARIABILITY_MAX = 80
    
    def __init__(self):
        self.active_sessions: Dict[str, BehaviorProfile] = {}
        self.monitoring_active = False
    
    def start_session(self, session_id: str) -> BehaviorProfile:
        """Start monitoring a new session."""
        profile = BehaviorProfile(session_id=session_id)
        self.active_sessions[session_id] = profile
        return profile
    
    def stop_session(self, session_id: str):
        """Stop monitoring a session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
    def record_keystroke(self, session_id: str, key: str, timestamp: float, 
                        field_id: str = None) -> Dict[str, Any]:
        """
        Record a keystroke event.
        
        Args:
            session_id: Unique session identifier
            key: The key pressed
            timestamp: Unix timestamp of keystroke
            field_id: Which input field
        
        Returns:
            Updated behavior analysis
        """
        if session_id not in self.active_sessions:
            self.start_session(session_id)
        
        profile = self.active_sessions[session_id]
        
        # Record keystroke
        keystroke = {
            'key': key,
            'timestamp': timestamp,
            'field': field_id,
            'time_since_last': 0
        }
        
        # Calculate time since last keystroke
        if profile.typing.keystrokes:
            last_time = profile.typing.keystrokes[-1]['timestamp']
            keystroke['time_since_last'] = timestamp - last_time
        
        profile.typing.keystrokes.append(keystroke)
        
        # Count backspaces (indicates human correction behavior)
        if key == 'Backspace':
            profile.typing.backspace_count += 1
        
        # Keep only last 100 keystrokes
        if len(profile.typing.keystrokes) > 100:
            profile.typing.keystrokes.pop(0)
        
        # Recalculate typing metrics
        self._analyze_typing(profile)
        
        # Update overall score
        self._calculate_overall_score(profile)
        
        return self._get_behavior_report(profile)
    
    def record_mouse_movement(self, session_id: str, x: float, y: float, 
                             timestamp: float) -> Dict[str, Any]:
        """Record mouse movement."""
        if session_id not in self.active_sessions:
            self.start_session(session_id)
        
        profile = self.active_sessions[session_id]
        
        movement = {
            'x': x,
            'y': y,
            'timestamp': timestamp,
            'speed': 0,
            'direction': 0
        }
        
        # Calculate speed and direction
        if profile.mouse.movements:
            last = profile.mouse.movements[-1]
            dx = x - last['x']
            dy = y - last['y']
            dt = timestamp - last['timestamp']
            
            if dt > 0:
                distance = (dx**2 + dy**2) ** 0.5
                movement['speed'] = distance / dt
                movement['direction'] = self._calculate_direction(dx, dy)
        
        profile.mouse.movements.append(movement)
        
        # Keep only last 200 movements
        if len(profile.mouse.movements) > 200:
            profile.mouse.movements.pop(0)
        
        # Analyze mouse behavior
        self._analyze_mouse(profile)
        
        # Update overall score
        self._calculate_overall_score(profile)
        
        return self._get_behavior_report(profile)
    
    def record_click(self, session_id: str, x: float, y: float, 
                    button: str, timestamp: float) -> Dict[str, Any]:
        """Record mouse click."""
        if session_id not in self.active_sessions:
            self.start_session(session_id)
        
        profile = self.active_sessions[session_id]
        
        click = {
            'x': x,
            'y': y,
            'button': button,
            'timestamp': timestamp,
            'hesitation': 0
        }
        
        # Calculate hesitation (time between last movement and click)
        if profile.mouse.movements:
            last_move = profile.mouse.movements[-1]
            click['hesitation'] = timestamp - last_move['timestamp']
        
        profile.mouse.clicks.append(click)
        
        # Keep only last 50 clicks
        if len(profile.mouse.clicks) > 50:
            profile.mouse.clicks.pop(0)
        
        return self._get_behavior_report(profile)
    
    def _analyze_typing(self, profile: BehaviorProfile):
        """Analyze typing patterns for human/bot detection."""
        keystrokes = profile.typing.keystrokes
        
        if len(keystrokes) < 5:
            return
        
        # Calculate typing speed
        if len(keystrokes) >= 10:
            time_span = keystrokes[-1]['timestamp'] - keystrokes[0]['timestamp']
            if time_span > 0:
                chars = len([k for k in keystrokes if len(k['key']) == 1])
                profile.typing.avg_typing_speed = (chars / time_span) * 60
        
        # Calculate consistency (humans have natural variation)
        intervals = [k['time_since_last'] for k in keystrokes if k['time_since_last'] > 0]
        if len(intervals) >= 5:
            try:
                mean_interval = statistics.mean(intervals)
                stdev_interval = statistics.stdev(intervals)
                
                # Coefficient of variation (lower = more consistent/bot-like)
                if mean_interval > 0:
                    cv = (stdev_interval / mean_interval) * 100
                    profile.typing.consistency_score = min(100, max(0, cv))
            except:
                profile.typing.consistency_score = 50
        
        # Calculate human likelihood
        profile.typing.human_likelihood = self._calculate_typing_human_score(profile.typing)
    
    def _analyze_mouse(self, profile: BehaviorProfile):
        """Analyze mouse movements for human/bot detection."""
        movements = profile.mouse.movements
        
        if len(movements) < 10:
            return
        
        # Calculate average speed
        speeds = [m['speed'] for m in movements if m['speed'] > 0]
        if speeds:
            profile.mouse.avg_speed = statistics.mean(speeds)
        
        # Calculate path curvature (humans move in curves, bots in straight lines)
        if len(movements) >= 3:
            curvatures = []
            for i in range(1, len(movements) - 1):
                prev_dir = movements[i-1]['direction']
                curr_dir = movements[i]['direction']
                next_dir = movements[i+1]['direction']
                
                # Calculate direction change
                dir_change = abs(curr_dir - prev_dir)
                if dir_change > 180:
                    dir_change = 360 - dir_change
                curvatures.append(dir_change)
            
            if curvatures:
                profile.mouse.path_curvature = statistics.mean(curvatures)
        
        # Calculate hesitation (humans pause before clicking)
        if profile.mouse.clicks:
            hesitations = [c['hesitation'] for c in profile.mouse.clicks if c['hesitation'] > 0]
            if hesitations:
                profile.mouse.hesitation_score = statistics.mean(hesitations)
        
        # Calculate human likelihood
        profile.mouse.human_likelihood = self._calculate_mouse_human_score(profile.mouse)
    
    def _calculate_typing_human_score(self, typing: TypingPattern) -> float:
        """Calculate how likely the typing is from a human (0-100)."""
        scores = []
        
        # Speed check
        if typing.avg_typing_speed > 0:
            if typing.avg_typing_speed < self.HUMAN_TYPING_SPEED_MIN:
                scores.append(30)  # Too slow, suspicious
            elif typing.avg_typing_speed > self.BOT_TYPING_SPEED_THRESHOLD:
                scores.append(10)  # Too fast, likely bot
            elif self.HUMAN_TYPING_SPEED_MIN <= typing.avg_typing_speed <= self.HUMAN_TYPING_SPEED_MAX:
                scores.append(90)  # Normal human speed
            else:
                scores.append(50)
        
        # Consistency check (humans have variation)
        if typing.consistency_score > 0:
            if typing.consistency_score < 10:  # Too consistent = bot
                scores.append(20)
            elif typing.consistency_score > 50:  # Natural variation = human
                scores.append(85)
            else:
                scores.append(60)
        
        # Backspace check (humans make mistakes)
        if typing.backspace_count > 0:
            scores.append(95)  # Making corrections is human
        elif len(typing.keystrokes) > 50:
            scores.append(40)  # Long text with no mistakes is suspicious
        
        return statistics.mean(scores) if scores else 50
    
    def _calculate_mouse_human_score(self, mouse: MousePattern) -> float:
        """Calculate how likely the mouse movement is from a human (0-100)."""
        scores = []
        
        # Curvature check (humans move in curves)
        if mouse.path_curvature > 0:
            if mouse.path_curvature < 5:  # Too straight = bot
                scores.append(20)
            elif mouse.path_curvature > 20:  # Natural curves = human
                scores.append(90)
            else:
                scores.append(60)
        
        # Speed check
        if mouse.avg_speed > 0:
            if mouse.avg_speed > 5000:  # Too fast = bot
                scores.append(15)
            elif mouse.avg_speed < 100:  # Very slow = suspicious
                scores.append(40)
            else:
                scores.append(80)
        
        # Hesitation check (humans pause)
        if mouse.hesitation_score > 0:
            if mouse.hesitation_score > 0.1:  # Natural hesitation
                scores.append(85)
            else:
                scores.append(50)
        
        return statistics.mean(scores) if scores else 50
    
    def _calculate_overall_score(self, profile: BehaviorProfile):
        """Calculate overall human likelihood score."""
        scores = []
        weights = []
        
        # Typing weight: 40%
        if profile.typing.human_likelihood > 0:
            scores.append(profile.typing.human_likelihood)
            weights.append(0.4)
        
        # Mouse weight: 40%
        if profile.mouse.human_likelihood > 0:
            scores.append(profile.mouse.human_likelihood)
            weights.append(0.4)
        
        # Touch weight: 20%
        if profile.touch.human_likelihood > 0:
            scores.append(profile.touch.human_likelihood)
            weights.append(0.2)
        
        if scores and weights:
            # Weighted average
            total_weight = sum(weights)
            profile.overall_human_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
            profile.confidence = min(100, (len(profile.typing.keystrokes) + len(profile.mouse.movements)) / 3)
        
        # Detect bot indicators
        profile.bot_indicators = self._detect_bot_indicators(profile)
        
        profile.last_updated = datetime.utcnow()
    
    def _detect_bot_indicators(self, profile: BehaviorProfile) -> List[str]:
        """Detect specific bot-like behaviors."""
        indicators = []
        
        # Typing indicators
        if profile.typing.avg_typing_speed > self.BOT_TYPING_SPEED_THRESHOLD:
            indicators.append('superhuman_typing_speed')
        
        if profile.typing.consistency_score < 5 and len(profile.typing.keystrokes) > 20:
            indicators.append('machine_like_consistency')
        
        if len(profile.typing.keystrokes) > 100 and profile.typing.backspace_count == 0:
            indicators.append('perfect_typing_no_errors')
        
        # Mouse indicators
        if profile.mouse.path_curvature < 2 and len(profile.mouse.movements) > 50:
            indicators.append('linear_mouse_movement')
        
        if profile.mouse.avg_speed > 10000:
            indicators.append('superhuman_mouse_speed')
        
        if profile.mouse.hesitation_score < 0.01 and len(profile.mouse.clicks) > 10:
            indicators.append('instant_clicks_no_hesitation')
        
        return indicators
    
    def _calculate_direction(self, dx: float, dy: float) -> float:
        """Calculate direction angle in degrees."""
        import math
        angle = math.degrees(math.atan2(dy, dx))
        return angle if angle >= 0 else angle + 360
    
    def _get_behavior_report(self, profile: BehaviorProfile) -> Dict[str, Any]:
        """Generate a behavior report for the frontend."""
        return {
            'human_score': round(profile.overall_human_score, 1),
            'confidence': round(profile.confidence, 1),
            'is_likely_human': profile.overall_human_score > 60,
            'is_suspicious': profile.overall_human_score < 40,
            'bot_indicators': profile.bot_indicators,
            'typing': {
                'speed_cpm': round(profile.typing.avg_typing_speed, 1),
                'human_score': round(profile.typing.human_likelihood, 1),
                'backspaces': profile.typing.backspace_count,
                'consistency': round(profile.typing.consistency_score, 1)
            },
            'mouse': {
                'avg_speed': round(profile.mouse.avg_speed, 1),
                'human_score': round(profile.mouse.human_likelihood, 1),
                'curvature': round(profile.mouse.path_curvature, 1),
                'hesitation': round(profile.mouse.hesitation_score, 3)
            },
            'risk_adjustment': self._get_risk_adjustment(profile)
        }
    
    def _get_risk_adjustment(self, profile: BehaviorProfile) -> Dict[str, Any]:
        """Determine how behavior affects risk score."""
        if profile.overall_human_score < 30:
            return {
                'level_increase': 2,
                'action': 'require_captcha',
                'message': 'Bot-like behavior detected. Additional verification required.'
            }
        elif profile.overall_human_score < 50:
            return {
                'level_increase': 1,
                'action': 'monitor_closely',
                'message': 'Suspicious behavior patterns detected.'
            }
        elif profile.bot_indicators:
            return {
                'level_increase': 1,
                'action': 'additional_verification',
                'message': f'Unusual patterns: {", ".join(profile.bot_indicators[:2])}'
            }
        else:
            return {
                'level_increase': 0,
                'action': 'normal',
                'message': 'Behavior consistent with human user'
            }
    
    def get_session_behavior(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current behavior analysis for a session."""
        if session_id not in self.active_sessions:
            return None
        return self._get_behavior_report(self.active_sessions[session_id])
    
    def get_all_active_behaviors(self) -> Dict[str, Dict[str, Any]]:
        """Get behavior analysis for all active sessions."""
        return {
            sid: self._get_behavior_report(profile)
            for sid, profile in self.active_sessions.items()
        }


# Global instance
_biometrics_instance = None

def get_biometrics() -> BehavioralBiometrics:
    """Get or create the global biometrics instance."""
    global _biometrics_instance
    if _biometrics_instance is None:
        _biometrics_instance = BehavioralBiometrics()
    return _biometrics_instance
