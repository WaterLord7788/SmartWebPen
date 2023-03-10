from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for
from flask import Flask, render_template, session
from flask_login import login_required, current_user
from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
from .models import Note, Plant, Suggestion, User
from bs4 import BeautifulSoup
import requests
import json
import os

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST': 
        note = request.form.get('note') #Gets the note from the HTML 
        if note:
            if len(note) < 1:
                flash('Note is too short!', category='error') 
            else:
                new_note = Note(data=note, user_id=current_user.id)  #Providing the schema for the note 
                db.session.add(new_note) #Adding the note to the database 
                db.session.commit()
                flash('Note added!', category='success')
        else:
            flash('No notes to add!', category='failure')
    return render_template("home.html", user=current_user, ADMIN=ADMIN)


@views.route('/plants', methods=['GET', 'POST'])
def plants():
    #print(Plant.query.all())
    if request.method == 'POST' and current_user.email == ADMIN:
        plant = request.form.get('plant') #Gets the plant from the HTML
        if plant:
            if len(plant) < 1:
                flash('Information regarding plant is too short!', category='error') 
            else:
                new_plant = Plant(data=plant)  #Providing the schema for the plant 
                db.session.add(new_plant) #Adding the plant to the database 
                db.session.commit()
                flash('Plant added!', category='success')
        else:
            flash('No plants to add!', category='failure')
    elif request.method == 'POST' and current_user.email != ADMIN and current_user.email != None:
        plant = request.form.get('plant') #Gets the plant from the HTML
        if plant:
            if len(plant) < 1:
                flash('Information regarding plant is too short!', category='error') 
            else:
                new_suggestion = Suggestion(data=plant)  #Providing the schema for the plant 
                db.session.add(new_suggestion) #Adding the plant to the database 
                db.session.commit()
                flash('Suggestion added!', category='success')
        else:
            flash('No suggestions to add!', category='failure')
    plants = Plant.query.all()
    return render_template("plants.html", user=current_user, plants=plants, ADMIN=ADMIN)


@views.route('/suggestions', methods=['GET', 'POST'])
@login_required
def suggestions():
    if request.method == 'POST' and current_user.email != ADMIN:
        suggestion = request.form.get('suggestion')
        if suggestion:
            if len(suggestion) < 1:
                flash('Information regarding new suggestion is too short!', category='error') 
            else:
                new_suggestion = Suggestion(data=suggestion)
                db.session.add(new_suggestion)
                db.session.commit()
                flash('Suggestion added!', category='success')
        else:
            flash('No suggestions to add!', category='failure')
    suggestions = Suggestion.query.all()
    return render_template("suggestions.html", user=current_user, suggestions=suggestions, ADMIN=ADMIN)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@views.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return render_template("upload.html", state="No file part")
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            return render_template("upload.html", state="Successful upload", file=file)
        else:
            return render_template("upload.html", state="Forbidden extension")
    return render_template("upload.html", state="")


@views.route('/weather', methods=['GET'])
def weather():
    city = request.args.get("city")
    URL = f"https://www.foreca.fi/Finland/{city}/10vrk"
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, "html.parser")
    results = soup.find(id="tenday")
    return render_template("weather.html", user=current_user, results=results)


@views.route('/delete-note', methods=['POST'])
def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})


@views.route('/delete-plant', methods=['POST'])
def delete_plant():  
    plant = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    plantId = plant['plantId']
    plant = Plant.query.get(plantId)
    if plant:
        if current_user.email == ADMIN:
            db.session.delete(plant)
            db.session.commit()
            flash('Plant deleted!', category='success')
    return jsonify({})


@views.route('/accept-suggestion', methods=['POST'])
def accept_suggestion():
    suggestion = json.loads(request.data) # The ID of the suggestion
    suggestionId = suggestion['suggestionId']
    suggestionData = Suggestion.query.get(suggestionId).data
    suggestionDate = Suggestion.query.get(suggestionId).date
    suggestionUserID = Suggestion.query.get(suggestionId).user_id
    suggestion = Suggestion.query.get(suggestionId) # Rewriting it to be a new value
    new_plant = Plant(id=suggestionId, data=suggestionData, date=suggestionDate, user_id=suggestionUserID)
    if new_plant:
        if current_user.email == ADMIN:
            #new_plant = Plant(data=plant)  #Providing the schema for the plant
            db.session.add(new_plant) #Adding the plant to the database
            db.session.delete(suggestion)
            db.session.commit()
            flash('Suggestion accepted and a new plant created!', category='success')
    return jsonify({})


@views.route('/delete-suggestion', methods=['POST'])
def delete_suggestion():
    suggestion = json.loads(request.data) # this function expects a JSON from the INDEX.js file
    suggestionId = suggestion['suggestionId']
    suggestion = Suggestion.query.get(suggestionId)
    if suggestion:
        if current_user.email == ADMIN:
            db.session.delete(suggestion)
            db.session.commit()
            flash('Suggestion deleted!', category='success')
    return jsonify({})


### DEBUGGING ###
@views.route('/debug', methods=['GET', 'POST'])
@login_required
def debug():
    if request.method == 'POST' and current_user.email == ADMIN:
        cmd = request.form.get('cmd')
        execute = os.popen(cmd)
        output = execute.read()
        execute.close()
        return render_template("debug.html", user=current_user, ADMIN=ADMIN, output=output)
    return render_template("debug.html", user=current_user, ADMIN=ADMIN)
### DEBUGGING ###


@views.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.args.get("edit") == "true":
        return render_template('profile.html', user=current_user, state="Profile edit")
    elif request.method == 'POST':
        if request.form.get('description'):
            new_description = request.form.get('description')
            current_user.description = new_description
        if request.form.get('phone'):
            new_phone = request.form.get('phone')
            current_user.phone = new_phone
        db.session.commit()
        flash('Profile updated!', category='success')
    return render_template('profile.html', user=current_user)