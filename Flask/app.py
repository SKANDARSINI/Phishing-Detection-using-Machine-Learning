from flask import Flask,render_template,request,redirect,url_for,session
import sqlite3
import requests
import pandas as pd
import hashlib
from urllib.parse import urlparse
import pickle


app = Flask(__name__)
app.secret_key = "youcanDOthis42"

def extract_features(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    path = parsed_url.path
    
    # creating various features from the URL
    features = [] 
    features.append(len(url)) #1
    features.append(len(hostname))#2
    features.append('.' in hostname and hostname.replace('.','').isdigit())#3
    features.append(hostname.count('.')) #4
    features.append(url.count('?')) #5
    features.append(url.count('=')) #6
    features.append(url.count('/')) #7
    features.append(hostname.startswith('www.')) #8
    features.append(sum(c.isdigit() for c in url)/float(len(url))) #9
    features.append(sum(c.isdigit() for c in hostname)/float(len(hostname)))#10
    features.append('.' in parsed_url.netloc[-4:])#11
    features.append('-' in hostname)#12
    features.append(min([len(word) for word in hostname.split('.')])) #13
    features.append(max([len(word) for word in hostname.split('.')]))#14
    features.append(max([len(word) for word in parsed_url.query.split('&')]))#15

    feature_names = ['length_url',
                     'length_hostname',
                     'ip',
                     'nb_dots',
                     'nb_qm',
                     'nb_eq',
                     'nb_slash',
                     'nb_www',
                     'ratio_digits_url',
                     'ratio_digits_host',
                     'tld_in_subdomain',
                     'prefix_suffix',
                     'shortest_word_host',
                     'longest_words_raw',
                     'longest_word_path']
    
    df = pd.DataFrame([features], columns=feature_names)
    
    return df

def predict_class(url):
    model = pickle.load(open('../baseline_clf.pkl', 'rb'))
    url_features = extract_features(url)
    features_final = url_features.values.reshape(1, -1)
    prediction = model.predict(features_final)[0]
    return "legitimate webpage" if prediction == 0 else "Caution: The website you are attempting to access may be a phishing site. Be careful not to share any sensitive information."

@app.route("/")
def index():
    return render_template('index.html')


def validate(username, password):
    conn = sqlite3.connect('../database.db')
    cur = conn.cursor()

    cur.execute('CREATE TABLE IF NOT EXISTS user (username TEXT, password TEXT);')
    conn.commit()

    cur.execute('SELECT * FROM user;')
    data = cur.fetchall()
    flag = 0
    for USER, PASS in data:
        if USER == username:
            flag = 1
            if PASS == password:
                return 1
            else:
                break

    if flag != 1:
        cur.execute('INSERT INTO user VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        return 1

    conn.close()
    return 0


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form['user']
        password = request.form['pass']

        if username == '' or password == '':
            return redirect(url_for('index'))
        
        if validate(username, password):
            session['user'] = username
            return redirect(url_for('home'))
        else:
            return redirect(url_for('index'))
        
    else:
        return render_template('index.html')



@app.route("/home", methods=["POST", "GET"])
def home():
    if 'user' in session:
        return render_template('home.html', user=session['user'])
    else:
        return render_template('index.html')


@app.route("/classification", methods=["POST", "GET"])
def classification():
    if 'user' in session:
        if request.method == "POST":
            try:
                url = request.form['url']            
                prediction = predict_class(url)
                result = f'url : {prediction}'
                return render_template('classification.html', prediction=result)
            except:
                result = 'Error: Invalid URL or Connection Error!'
                return render_template('classification.html', prediction=result)
        else:
            return render_template('classification.html')
    return redirect(url_for('index'))



@app.route("/logout")
def logout():
    if "user" in session:
        session.pop("user", None)
    return redirect(url_for('index'))