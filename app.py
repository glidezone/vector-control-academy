from __future__ import annotations

from datetime import datetime
from typing import Optional, Dict, List
import os

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash


# -------------------------
# App / DB setup
# -------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-in-production"

db_uri = os.environ.get("DATABASE_URL", "sqlite:///vector_control_academy.db")
if db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# -------------------------
# Models
# -------------------------


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    discord_tag = db.Column(db.String(64), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_mentor = db.Column(db.Boolean, default=False, nullable=False)
    rating_awarded = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    signups = db.relationship(
        "ModuleSignup",
        back_populates="user",
        foreign_keys="ModuleSignup.user_id",
    )
    support_threads = db.relationship("SupportThread", back_populates="creator")

    reports_received = db.relationship(
        "SessionReport",
        foreign_keys="SessionReport.trainee_id",
        backref="trainee_user",
    )
    reports_written = db.relationship(
        "SessionReport",
        foreign_keys="SessionReport.mentor_id",
        backref="mentor_user",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(16), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    stage = db.Column(db.Integer, nullable=False)  # 1,2,3,4
    avg_weekly_capacity = db.Column(db.Integer, default=4, nullable=False)

    signups = db.relationship("ModuleSignup", back_populates="module")


class ModuleSignup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    module_id = db.Column(db.Integer, db.ForeignKey("module.id"), nullable=False)
    mentor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    status = db.Column(
        db.String(16), nullable=False, default="waiting"
    )  # waiting / in_progress / completed / failed

    notes = db.Column(db.Text, nullable=True)
    priority = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", foreign_keys=[user_id], back_populates="signups")
    module = db.relationship("Module", back_populates="signups")
    mentor = db.relationship(
        "User", foreign_keys=[mentor_id], backref="mentored_signups"
    )


class SupportThread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_closed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    creator = db.relationship("User", back_populates="support_threads")
    messages = db.relationship(
        "SupportMessage", back_populates="thread", cascade="all, delete-orphan"
    )


class SupportMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey("support_thread.id"), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    thread = db.relationship("SupportThread", back_populates="messages")
    author = db.relationship("User")


class SessionReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trainee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    mentor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    module_id = db.Column(db.Integer, db.ForeignKey("module.id"), nullable=True)

    subject = db.Column(db.String(255), nullable=False)
    topic = db.Column(db.String(255), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    grade = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    trainee = db.relationship(
        "User",
        foreign_keys=[trainee_id],
        primaryjoin="SessionReport.trainee_id==User.id",
    )
    mentor = db.relationship(
        "User",
        foreign_keys=[mentor_id],
        primaryjoin="SessionReport.mentor_id==User.id",
    )
    module = db.relationship("Module")


class RatingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(16), default="pending", nullable=False)
    admin_comment = db.Column(db.Text, nullable=True)

    user = db.relationship("User")


# -------------------------
# Login
# -------------------------


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return db.session.get(User, int(user_id))


# -------------------------
# Helpers
# -------------------------


def mentor_required(view):
    @login_required
    def wrapped(*args, **kwargs):
        if not (current_user.is_admin or current_user.is_mentor):
            flash("Mentor permissions required.", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__
    return wrapped


def admin_required(view):
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            flash("Admin permissions required.", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__
    return wrapped


def get_user_module_status(user: User, module: Module) -> Optional[ModuleSignup]:
    return ModuleSignup.query.filter_by(user_id=user.id, module_id=module.id).first()


def prerequisites_met(user: User, module: Module) -> bool:
    # C1 always available
    if module.code == "C1":
        return True

    # Need completed C1 for C2
    if module.code == "C2":
        c1_done = (
            ModuleSignup.query.join(Module)
            .filter(
                ModuleSignup.user_id == user.id,
                Module.code == "C1",
                ModuleSignup.status == "completed",
            )
            .first()
        )
        return c1_done is not None

    # Need completed C2 for C3
    if module.code == "C3":
        c2_done = (
            ModuleSignup.query.join(Module)
            .filter(
                ModuleSignup.user_id == user.id,
                Module.code == "C2",
                ModuleSignup.status == "completed",
            )
            .first()
        )
        return c2_done is not None

    return True


def module_queue(module: Module) -> List[ModuleSignup]:
    """Waiting list for a module ordered by priority (FIFO)."""
    return (
        ModuleSignup.query.filter_by(module_id=module.id, status="waiting")
        .order_by(ModuleSignup.priority.desc(), ModuleSignup.created_at.asc())
        .all()
    )


def queue_position(signup: ModuleSignup) -> Optional[int]:
    """1-based position in queue, or None if not waiting."""
    if signup.status != "waiting":
        return None
    queue = module_queue(signup.module)
    try:
        return queue.index(signup) + 1
    except ValueError:
        return None


def estimate_wait_time(module: Module, queue_len: int) -> str:
    """Very rough text estimate based on avg_weekly_capacity."""
    capacity = module.avg_weekly_capacity or 1
    weeks = (queue_len + capacity - 1) // capacity
    if weeks <= 0:
        return "Less than 1 week"
    if weeks == 1:
        return "Around 1 week"
    return f"Approximately {weeks} weeks"


def user_completed_all_modules(user: User, modules: List[Module]) -> bool:
    """Check if user has status 'completed' for all modules."""
    for m in modules:
        completed = ModuleSignup.query.filter_by(
            user_id=user.id, module_id=m.id, status="completed"
        ).first()
        if not completed:
            return False
    return True


def waiting_signup_for_user(user: User) -> Optional[ModuleSignup]:
    """Return any signup where user is still in waiting or in_progress."""
    return (
        ModuleSignup.query.filter(
            ModuleSignup.user_id == user.id,
            ModuleSignup.status.in_(["waiting", "in_progress"]),
        )
        .first()
    )


# -------------------------
# Routes – public
# -------------------------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


# -------------------------
# Auth
# -------------------------

@app.route("/super_admin_power")
@login_required
def super_admin_power():
    if not current_user.is_admin:
        return "Not allowed.", 403

    user = User.query.filter_by(email="frederikwildau1@gmail.com").first()
    if user:
        user.is_admin = True
        db.session.commit()
        return "Admin granted successfully to " + user.full_name
    return "User not found!"


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        discord_tag = request.form.get("discord_tag", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not name or not email or not discord_tag or not password or not password2:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for("register"))

        if password != password2:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("This email is already registered.", "danger")
            return redirect(url_for("register"))

        user = User(
            full_name=name,
            email=email,
            discord_tag=discord_tag,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("Logged in successfully.", "success")
        return redirect(url_for("modules_view"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


# -------------------------
# Modules & signups
# -------------------------


@app.route("/modules")
@login_required
def modules_view():
    modules = Module.query.order_by(Module.stage.asc()).all()
    signups_by_module: Dict[int, ModuleSignup] = {}
    permissions: Dict[int, Dict[str, str]] = {}
    positions: Dict[int, int] = {}
    estimates: Dict[int, str] = {}

    for m in modules:
        signup = get_user_module_status(current_user, m)
        if signup:
            signups_by_module[m.id] = signup
            pos = queue_position(signup)
            if pos:
                positions[m.id] = pos

        # Permission to join
        if signup:
            permissions[m.id] = {
                "allowed": False,
                "message": "Already registered for this module.",
            }
        else:
            if not prerequisites_met(current_user, m):
                permissions[m.id] = {
                    "allowed": False,
                    "message": "Prerequisites not met yet.",
                }
            else:
                # Only one waiting module at a time
                other_waiting = waiting_signup_for_user(current_user)
                if other_waiting:
                    permissions[m.id] = {
                        "allowed": False,
                        "message": "You can only be registered for one module at a time.",
                    }
                else:
                    permissions[m.id] = {"allowed": True, "message": ""}

        q_len = len(module_queue(m))
        estimates[m.id] = estimate_wait_time(m, q_len)

    # Rating prompt
    show_rating_prompt = False
    rating_request = None
    if current_user.is_authenticated:
        rating_request = RatingRequest.query.filter_by(
            user_id=current_user.id
        ).order_by(RatingRequest.created_at.desc()).first()
        if (
            not current_user.rating_awarded
            and (not rating_request or rating_request.status != "pending")
            and user_completed_all_modules(current_user, modules)
        ):
            show_rating_prompt = True

    return render_template(
        "modules.html",
        modules=modules,
        user_signups=signups_by_module,
        permissions=permissions,
        positions=positions,
        estimates=estimates,
        show_rating_prompt=show_rating_prompt,
        rating_request=rating_request,
    )


@app.route("/modules/signup/<int:module_id>", methods=["POST"])
@login_required
def signup_module(module_id: int):
    module = Module.query.get_or_404(module_id)

    if not prerequisites_met(current_user, module):
        flash("You do not meet the prerequisites for this module.", "danger")
        return redirect(url_for("modules_view"))

    existing = get_user_module_status(current_user, module)
    if existing:
        flash("You are already registered for this module.", "danger")
        return redirect(url_for("modules_view"))

    other_waiting = waiting_signup_for_user(current_user)
    if other_waiting:
        flash(
            "You can only be registered for one module at a time. "
            "Finish or withdraw from your current module first.",
            "danger",
        )
        return redirect(url_for("modules_view"))

    # queue position based on current min priority (FIFO)
    # earlier signups keep a higher priority value; new signups get lower
    min_priority = (
        db.session.query(db.func.min(ModuleSignup.priority))
        .filter_by(module_id=module.id)
        .scalar()
    )
    if min_priority is None:
        new_priority = 0
    else:
        new_priority = min_priority - 1

    signup = ModuleSignup(
        user_id=current_user.id,
        module_id=module.id,
        status="waiting",
        priority=new_priority,
    )
    db.session.add(signup)
    db.session.commit()

    flash(f"You joined the waiting list for {module.title}.", "success")
    return redirect(url_for("modules_view"))


@app.route("/modules/withdraw/<int:module_id>", methods=["POST"])
@login_required
def withdraw_module(module_id: int):
    module = Module.query.get_or_404(module_id)
    signup = get_user_module_status(current_user, module)
    if not signup or signup.status != "waiting":
        flash("You are not on the waiting list for this module.", "danger")
        return redirect(url_for("modules_view"))

    db.session.delete(signup)
    db.session.commit()
    flash(f"You have been removed from the waiting list for {module.title}.", "success")
    return redirect(url_for("modules_view"))


@app.route("/my")
@login_required
def my_signups():
    signups = ModuleSignup.query.filter_by(user_id=current_user.id).order_by(
        ModuleSignup.created_at.asc()
    )
    positions: Dict[int, int] = {}
    for s in signups:
        pos = queue_position(s)
        if pos:
            positions[s.id] = pos

    rating_request = RatingRequest.query.filter_by(user_id=current_user.id).order_by(
        RatingRequest.created_at.desc()
    ).first()

    return render_template(
        "my_signups.html", signups=signups, positions=positions, rating_request=rating_request
    )


@app.route("/request_rating", methods=["POST"])
@login_required
def request_rating():
    modules = Module.query.order_by(Module.stage.asc()).all()
    if not user_completed_all_modules(current_user, modules):
        flash("You must complete all modules before requesting a rating.", "danger")
        return redirect(url_for("modules_view"))

    if current_user.rating_awarded:
        flash(
            "Your Vector Control Academy rating has already been awarded. Congratulations!",
            "success",
        )
        return redirect(url_for("modules_view"))

    existing = RatingRequest.query.filter_by(
        user_id=current_user.id, status="pending"
    ).first()
    if existing:
        flash("You already have a pending rating request.", "info")
        return redirect(url_for("modules_view"))

    req = RatingRequest(user_id=current_user.id)
    db.session.add(req)
    db.session.commit()
    flash("Rating request submitted. An admin will review it.", "success")
    return redirect(url_for("modules_view"))


# -------------------------
# Support
# -------------------------


@app.route("/support", methods=["GET", "POST"])
@login_required
def support():
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        if not subject or not body:
            flash("Please fill in subject and message.", "danger")
            return redirect(url_for("support"))

        thread = SupportThread(subject=subject, created_by_id=current_user.id)
        db.session.add(thread)
        db.session.flush()
        msg = SupportMessage(thread_id=thread.id, author_id=current_user.id, body=body)
        db.session.add(msg)
        db.session.commit()
        flash("Support ticket created.", "success")
        return redirect(url_for("support_thread", thread_id=thread.id))

    if current_user.is_admin or current_user.is_mentor:
        threads = SupportThread.query.order_by(SupportThread.created_at.desc()).all()
    else:
        threads = (
            SupportThread.query.filter_by(created_by_id=current_user.id)
            .order_by(SupportThread.created_at.desc())
            .all()
        )

    return render_template("support.html", threads=threads)


@app.route("/support/<int:thread_id>", methods=["GET", "POST"])
@login_required
def support_thread(thread_id: int):
    thread = SupportThread.query.get_or_404(thread_id)

    if not (
        current_user.is_admin
        or current_user.is_mentor
        or thread.created_by_id == current_user.id
    ):
        flash("You do not have access to this ticket.", "danger")
        return redirect(url_for("support"))

    if request.method == "POST":
        if thread.is_closed:
            flash("This ticket is closed.", "danger")
            return redirect(url_for("support_thread", thread_id=thread.id))

        body = request.form.get("body", "").strip()
        if not body:
            flash("Message cannot be empty.", "danger")
            return redirect(url_for("support_thread", thread_id=thread.id))

        msg = SupportMessage(
            thread_id=thread.id, author_id=current_user.id, body=body
        )
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("support_thread", thread_id=thread.id))

    return render_template("support_thread.html", thread=thread)


@app.route("/support/<int:thread_id>/close", methods=["POST"])
@login_required
def close_support_thread(thread_id: int):
    thread = SupportThread.query.get_or_404(thread_id)
    if not (
        current_user.is_admin
        or current_user.is_mentor
        or thread.created_by_id == current_user.id
    ):
        flash("You do not have permission to close this ticket.", "danger")
        return redirect(url_for("support"))
    thread.is_closed = True
    db.session.commit()
    flash("Ticket closed.", "success")
    return redirect(url_for("support_thread", thread_id=thread.id))


# -------------------------
# Session reports
# -------------------------


@app.route("/reports")
@login_required
def reports():
    if current_user.is_admin or current_user.is_mentor:
        trainee_id = request.args.get("trainee_id", type=int)
        if trainee_id:
            reports = (
                SessionReport.query.filter_by(trainee_id=trainee_id)
                .order_by(SessionReport.created_at.desc())
                .all()
            )
        else:
            reports = SessionReport.query.order_by(
                SessionReport.created_at.desc()
            ).all()
        trainees = User.query.order_by(User.full_name.asc()).all()
    else:
        reports = (
            SessionReport.query.filter_by(trainee_id=current_user.id)
            .order_by(SessionReport.created_at.desc())
            .all()
        )
        trainees = None

    return render_template("reports.html", reports=reports, trainees=trainees)


@app.route("/reports/new", methods=["GET", "POST"])
@mentor_required
def new_report():
    if request.method == "POST":
        trainee_id = request.form.get("trainee_id", type=int)
        module_id = request.form.get("module_id", type=int)
        subject = request.form.get("subject", "").strip()
        topic = request.form.get("topic", "").strip()
        comment = request.form.get("comment", "").strip()
        grade_raw = request.form.get("grade", "").strip()

        if not trainee_id or not subject:
            flash("Please select a trainee and enter a subject.", "danger")
            return redirect(url_for("new_report"))

        grade = None
        if grade_raw:
            try:
                grade_val = int(grade_raw)
            except ValueError:
                flash("Grade must be a number between 1 and 10.", "danger")
                return redirect(url_for("new_report"))
            if not (1 <= grade_val <= 10):
                flash("Grade must be between 1 and 10.", "danger")
                return redirect(url_for("new_report"))
            grade = grade_val

        trainee = User.query.get_or_404(trainee_id)
        module = Module.query.get(module_id) if module_id else None

        report = SessionReport(
            trainee_id=trainee.id,
            mentor_id=current_user.id,
            module_id=module.id if module else None,
            subject=subject,
            topic=topic or None,
            comment=comment or None,
            grade=grade,
        )
        db.session.add(report)
        db.session.commit()
        flash("Session report created.", "success")
        return redirect(url_for("reports", trainee_id=trainee.id))

    trainees = User.query.order_by(User.full_name.asc()).all()
    modules = Module.query.order_by(Module.stage.asc(), Module.code.asc()).all()
    return render_template("report_new.html", trainees=trainees, modules=modules)


# -------------------------
# Mentor
# -------------------------


@app.route("/mentor")
@mentor_required
def mentor_dashboard():
    modules = Module.query.order_by(Module.stage.asc()).all()

    # Active signups assigned to this mentor
    my_active = (
        ModuleSignup.query.filter(
            ModuleSignup.mentor_id == current_user.id,
            ModuleSignup.status == "waiting",
        )
        .order_by(ModuleSignup.last_updated.desc())
        .all()
    )

    module_queues: Dict[int, List[ModuleSignup]] = {}
    for m in modules:
        module_queues[m.id] = module_queue(m)

    return render_template(
        "mentor_dashboard.html",
        modules=modules,
        my_active=my_active,
        module_queues=module_queues,
    )


@app.route("/mentor/pick/<int:signup_id>", methods=["POST"])
@mentor_required
def mentor_pick(signup_id: int):
    signup = ModuleSignup.query.get_or_404(signup_id)
    if signup.status != "waiting":
        flash("This trainee is not in waiting status.", "danger")
        return redirect(url_for("mentor_dashboard"))

    signup.mentor_id = current_user.id
    signup.last_updated = datetime.utcnow()
    db.session.commit()
    flash("Trainee assigned to you.", "success")
    return redirect(url_for("mentor_dashboard"))


@app.route("/mentor/update/<int:signup_id>", methods=["POST"])
@mentor_required
def mentor_update(signup_id: int):
    signup = ModuleSignup.query.get_or_404(signup_id)

    if signup.mentor_id not in {current_user.id} and not current_user.is_admin:
        flash("You are not assigned to this trainee.", "danger")
        return redirect(url_for("mentor_dashboard"))

    status = request.form.get("status", "waiting")
    notes = request.form.get("notes", "").strip()

    if status not in {"waiting", "in_progress", "completed", "failed"}:
        flash("Invalid status.", "danger")
        return redirect(url_for("mentor_dashboard"))

    # Handle M1/M2 failure rule (legacy codes; currently not used with C1/C2/C3)
    module_code = signup.module.code
    if status == "failed" and module_code in {"M1", "M2"}:
        # Remove all signups and rating requests for that user
        ModuleSignup.query.filter_by(user_id=signup.user_id).delete()
        RatingRequest.query.filter_by(user_id=signup.user_id).delete()
        db.session.commit()
        flash(
            "Trainee failed Module 1/2. All registrations removed – they must start again from Module 1.",
            "warning",
        )
        return redirect(url_for("mentor_dashboard"))

    signup.status = status
    if notes:
        signup.notes = (signup.notes or "") + f"\n[{datetime.utcnow().isoformat()}] {notes}"
    signup.last_updated = datetime.utcnow()
    db.session.commit()
    flash("Signup updated.", "success")
    return redirect(url_for("mentor_dashboard"))


# -------------------------
# Admin
# -------------------------


@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.full_name.asc()).all()
    modules = Module.query.order_by(Module.stage.asc()).all()
    all_signups = ModuleSignup.query.order_by(ModuleSignup.created_at.asc()).all()
    rating_requests = RatingRequest.query.order_by(
        RatingRequest.created_at.asc()
    ).all()

    signup_rows = []
    for s in all_signups:
        pos = queue_position(s)
        signup_rows.append(
            {
                "signup": s,
                "user": s.user,
                "module": s.module,
                "position": pos,
            }
        )

    stats = {
        "total_users": User.query.count(),
        "total_modules": Module.query.count(),
        "total_signups": ModuleSignup.query.count(),
        "pending_ratings": RatingRequest.query.filter_by(status="pending").count(),
    }

    return render_template(
        "admin_dashboard.html",
        users=users,
        modules=modules,
        signup_rows=signup_rows,
        stats=stats,
        rating_requests=rating_requests,
    )


@app.route("/admin/user/<int:user_id>/toggle_mentor", methods=["POST"])
@admin_required
def admin_toggle_mentor(user_id: int):
    user = User.query.get_or_404(user_id)
    user.is_mentor = not user.is_mentor
    db.session.commit()
    flash("Mentor flag updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/signup/<int:signup_id>/status", methods=["POST"])
@admin_required
def admin_update_signup_status(signup_id: int):
    signup = ModuleSignup.query.get_or_404(signup_id)
    status = request.form.get("status", "waiting")
    if status not in {"waiting", "in_progress", "completed", "failed"}:
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_dashboard"))

    signup.status = status
    signup.last_updated = datetime.utcnow()
    db.session.commit()
    flash("Status updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/signup/<int:signup_id>/move", methods=["POST"])
@admin_required
def admin_move_signup(signup_id: int):
    direction = request.form.get("direction", "up")
    signup = ModuleSignup.query.get_or_404(signup_id)
    queue = module_queue(signup.module)

    if signup not in queue:
        flash("Only waiting signups can be moved.", "danger")
        return redirect(url_for("admin_dashboard"))

    idx = queue.index(signup)
    if direction == "up" and idx > 0:
        other = queue[idx - 1]
    elif direction == "down" and idx < len(queue) - 1:
        other = queue[idx + 1]
    else:
        other = None

    if other:
        signup.priority, other.priority = other.priority, signup.priority
        db.session.commit()
        flash("Queue order updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/signup/<int:signup_id>/kick", methods=["POST"])
@admin_required
def admin_kick_signup(signup_id: int):
    signup = ModuleSignup.query.get_or_404(signup_id)
    db.session.delete(signup)
    db.session.commit()
    flash("Signup removed from queue.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/rating/<int:req_id>", methods=["POST"])
@admin_required
def admin_update_rating_request(req_id: int):
    req = RatingRequest.query.get_or_404(req_id)
    status = request.form.get("status", "pending")
    comment = request.form.get("comment", "").strip()

    if status not in {"pending", "approved", "denied"}:
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_dashboard"))

    req.status = status
    req.admin_comment = comment or None

    if status == "approved":
        user = req.user
        user.rating_awarded = True

    db.session.commit()
    flash("Rating request updated.", "success")
    return redirect(url_for("admin_dashboard"))


# -------------------------
# DB seeding / CLI
# -------------------------

def seed_modules_and_admin():

    if Module.query.count() == 0:
        modules = [
            Module(
                code="C1",
                title="C1 - GND / DEL",
                description="Ground and Delivery operations: clearances, pushback, start-up, taxi routing and basic coordination.",
                stage=1,
                avg_weekly_capacity=6,
            ),
            Module(
                code="C2",
                title="C2 - TWR",
                description="Tower operations: departures, arrivals, circuit traffic, runway crossings and sequencing.",
                stage=2,
                avg_weekly_capacity=5,
            ),
            Module(
                code="C3",
                title="C3 - APP",
                description="Approach operations: vectoring, intermediate approach, holdings, missed approaches and coordination.",
                stage=3,
                avg_weekly_capacity=4,
            ),
        ]
        db.session.add_all(modules)

    # Seed admin user
    admin_email = "kristkrunk@gmail.com"
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(
            email=admin_email,
            full_name="Vector Admin",
            discord_tag="krist#0000",
            is_admin=True,
            is_mentor=True,
        )
        admin.set_password("Miksas123@")
        db.session.add(admin)

    db.session.commit()


@app.cli.command("init-db")
def init_db_command():
    """Drop and recreate all tables, then seed modules and admin."""
    db.drop_all()
    db.create_all()
    seed_modules_and_admin()
    print("Database initialised.")


# -------------------------
# Run
# -------------------------
@app.route("/give_admin_frederik")
@login_required
def give_admin_frederik():
    if not current_user.is_admin:
        return "Not allowed", 403

    user = User.query.filter_by(email="frederikwildau1@gmail.com").first()
    if not user:
        return "User not found"
    user.is_admin = True
    db.session.commit()
    return "Admin granted to " + user.email


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_modules_and_admin()
    app.run(debug=True)
