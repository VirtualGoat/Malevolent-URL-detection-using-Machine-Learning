from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix,accuracy_score
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
import pickle
from sklearn.model_selection import GridSearchCV

legitimate_urls = pd.read_csv("generated_features/good-urls.csv")
phishing_urls = pd.read_csv("generated_features/bad-urls.csv")

urls = legitimate_urls.append(phishing_urls)

#Then URL text details are not required
urls = urls.drop(urls.columns[[0,1,2]],axis=1)

urls = urls.sample(frac=1).reset_index(drop=True)
urls_without_labels = urls.drop('label',axis=1)

labels = urls['label']
X_train, x_test, Y_train, y_test = train_test_split(urls_without_labels, labels, test_size=0.30, random_state=100)

'''
-----------------------Using GridSearchCV on RandomForest------------------------------
param_grid = {
'bootstrap': [True],
'max_depth': [80, 90, 100, 110],
'max_features': ['auto', 'sqrt', 'log2'],
'min_samples_leaf': [3, 4, 5],
'min_samples_split': [8, 10, 12],
'n_estimators': [100, 200, 300, 1000]
}

rf = RandomForestClassifier()
# Instantiate the grid search model

grid_search = GridSearchCV(estimator = rf, param_grid = param_grid, 
cv = 3, n_jobs = -1, verbose = 2)

# Fit the grid search to the data
grid_search.fit(X_train, Y_train)
alpha = grid_search.best_params_

best_grid = grid_search.best_estimator_
print (alpha)
print (best_grid)
-----------------------Training the classifier------------------------------
rf=RandomForestClassifier(bootstrap=True, class_weight=None, criterion='gini',
            max_depth=80, max_features='log2', max_leaf_nodes=None,
            min_impurity_decrease=0.0, min_impurity_split=None,
            min_samples_leaf=3, min_samples_split=10,
            min_weight_fraction_leaf=0.0, n_estimators=200, n_jobs=None,
            oob_score=False, random_state=None, verbose=0,
            warm_start=False)

rf.fit(X_train,Y_train)
pred_label = rf.predict(x_test)
'''

'''
classifier=SVC(kernel='rbf',random_state=0)


classifier.fit(X_train,Y_train)

y_pred = classifier.predict(x_test)

cm=confusion_matrix(y_test,y_pred)

print(accuracy_score(y_test,y_pred))
'''

DTmodel = DecisionTreeClassifier(class_weight=None, criterion='gini', max_depth=15,
            max_features=None, max_leaf_nodes=None,
            min_impurity_decrease=0.0, min_impurity_split=None,
            min_samples_leaf=1, min_samples_split=10,
            min_weight_fraction_leaf=0.0, presort=False, random_state=None,
            splitter='best')
DTmodel.fit(X_train,Y_train)
pred_label = DTmodel.predict(x_test)


#cm = confusion_matrix(y_test,pred_label)
#print(accuracy_score(y_test,pred_label))



'''
parameters={'min_samples_split' : range(10,500,20),'max_depth': range(1,20,2)}
tree=DecisionTreeClassifier()

grid_search = GridSearchCV(tree,parameters)
grid_search.fit(X_train,Y_train)
alpha = grid_search.best_params_
best_grid = grid_search.best_estimator_
print (alpha)
print (best_grid)
'''





'''
'''

cm = confusion_matrix(y_test,pred_label)
print(accuracy_score(y_test,pred_label))
prec=cm[1,1]/(cm[0,1]+cm[1,1])
reca=cm[1,1]/(cm[1,0]+cm[1,1])

print("Precision: ",prec)
print("Recall: ",reca)
'''
file= 'random_forest.pkl'
with open(file,'wb') as f:
    pickle.dump(rf,f)
f.close()
 


'''