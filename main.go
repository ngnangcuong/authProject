package main

import (
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"

	"log"
	"fmt"
	"html/template"
	"net/http"
	"time"
	"strings"
)

var (
	router *mux.Router
	mySigningKey = "pa$$w0rd"
	templates = template.Must(template.ParseFiles("authProj/views/index.html", "authProj/views/login.html", "authProj/views/register.html", "authProj/views/indexRole.html"))
	userList []*User
)

// ----------------- MODELS --------------------------------

type User struct {
	gorm.Model
	Email 	string `gorm:"unique" json:"email"`
	Name 	string `json:"name"`
	Password 	string `json:"password"`
	Role 	string `json:"role"`
}

type Authencation struct {
	Email 	string `json:"email"`
	Password 	string `json:"password"`
}

type Error struct {
	IsError 	bool `json:"isError"`
	Message 	string `json:"message"`
}

type Job struct {
	Name 	string `json:"role"`
	Permission	string `json:"permission"`
}

func SetError(err *Error, message string) *Error{
	err.IsError = true
	err.Message = message
	return err
}

// ----------- DATABASE -------------------------------

func GetDatabase() *gorm.DB {
	dbname := "Userjwt"
	db := "postgres"
	dbpassword := "Cuongnguyen2001"
	dburl := "postgres://postgres:" + dbpassword + "@localhost/" + dbname + "?sslmode=disable"
	connection, err := gorm.Open(db, dburl)

	if err != nil {
		log.Fatalln("Wrong database url")
	}

	sqldb := connection.DB()
	err = sqldb.Ping()
	if err != nil {
		log.Fatalln("Database connected")
	}
	fmt.Println("Database is connected")

	return connection
}

func InitMigration() {
	connection := GetDatabase()
	defer CloseDatabase(connection)
	connection.AutoMigrate(User{})
	connection.AutoMigrate(Job{})
}


func CloseDatabase(connection *gorm.DB) {
	sqldb := connection.DB()
	sqldb.Close()
}

// --------------- ROUTES -----------------------------
func InitRoute() {
	router = mux.NewRouter()

	router.HandleFunc("/user", IsSignIn(Index)).Methods("GET")
	router.HandleFunc("/user/login", ShowLogIn).Methods("GET")
	router.HandleFunc("/user/register", ShowRegister).Methods("GET")
	router.HandleFunc("/user/signup", SignUp).Methods("POST")
	router.HandleFunc("/user/signin", SignIn).Methods("POST")
	router.HandleFunc("/user/logout", LogOut).Methods("GET")
	router.HandleFunc("/create-role", IsSignIn(CreateRole)).Methods("POST")
	router.HandleFunc("/role/new-role", RoleIndex).Methods("GET")
	router.HandleFunc("/user/delete-user/{userEmail}", IsSignIn(DeleteUser)).Methods("DELETE")
	router.HandleFunc("/user/create-user", IsSignIn(CreateUser)).Methods("POST")
	router.HandleFunc("/user/update-user/{userEmail}", IsSignIn(UpdateUser)).Methods("PATCH")
	router.HandleFunc("role//change-role", IsSignIn(ChangeRole)).Methods("PUT")
	router.Methods("OPTIONS").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Access-Control-Request-Headers, Access-Control-Request-Method, Connection, Host, Origin, User-Agent, Referer, Cache-Control, X-header")

	})
}

func ServerStart() {
	fmt.Println("Server start at port 8080")

	err := http.ListenAndServe(":8080", router)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

// ------------------ HELPER FUNCTION --------------------------

func renderTemplate(w http.ResponseWriter, tmpl string, message string) {
	err := templates.ExecuteTemplate(w, tmpl + ".html", Error{
		IsError: message != "",
		Message: message,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func GeneratehashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func GenerateJWT(userauth *User) (string, error) {
	var secretkey = []byte(mySigningKey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorization"] = true
	claims["email"] = userauth.Email
	claims["role"] = userauth.Role
	claims["name"] = userauth.Name
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(secretkey)

	if err != nil {
		fmt.Printf("Something went wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --------------- HANDLER FUNCTION ---------------------------------
func Index(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)
	var userList []User
	connection.Find(&userList)

	err := templates.ExecuteTemplate(w, "index.html", userList)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func ShowLogIn(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func ShowRegister(w http.ResponseWriter, r *http.Request) {
	mis := Error{
		IsError: false,
		Message: "",
	}
	err := templates.ExecuteTemplate(w, "register.html", mis)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}


func IsSignIn(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("Token");
		if cookie == nil {
			fmt.Println("No Token found")
			w.Write([]byte("Failed to collect token"))
			return
		}

		var secretkey = []byte(mySigningKey)
		tokenString, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing")
			}
			return secretkey, nil
		})

		if err != nil {
			fmt.Println("Token is invalid")
			return
		}

		if claims, ok := tokenString.Claims.(jwt.MapClaims); ok && tokenString.Valid {
			email := claims["email"].(string)
			role := claims["role"].(string)
			r.Header.Add("Email", email)
			r.Header.Add("Role", role)
			handler.ServeHTTP(w, r)
			return
		}
		
	}
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	name := r.FormValue("name")
	password := r.FormValue("password")
	connection := GetDatabase()
	defer CloseDatabase(connection)

	if email == "" || name == "" || password == "" {
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	var usertmp User
	connection.Where("email = ?", email).First(&usertmp)
	
	if usertmp.Email != "" {
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	password, err := GeneratehashPassword(password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	var user User = User{
		Email: email,
		Name: name,
		Password: password,
		Role: "user",
	}

	connection.Create(&user)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	email := r.FormValue("email")
	password := r.FormValue("password")
	fmt.Println(email, password)

	var userauth User
	connection.Where("email = ?", email).First(&userauth)

	if userauth.Email == "" {
		w.Write([]byte("Not User"))
		fmt.Println("not user")

		return
	}

	check := CheckPasswordHash(password, userauth.Password)
	if !check {
		w.Write([]byte("Wrong password"))
		fmt.Println("wrong password")

		return
	}

	tokenString, err := GenerateJWT(&userauth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println(tokenString)
	exp := time.Now().Add(5 * time.Minute)
	cookie := http.Cookie{Name: "Token", Value: tokenString, Expires: exp, HttpOnly: true}
	http.SetCookie(w, &cookie)
}

func RoleIndex(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	var jobs []Job
	connection.Find(&jobs)
	err := templates.ExecuteTemplate(w, "indexRole.html", jobs)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func CreateRole(w http.ResponseWriter, r *http.Request) {
	if role := r.Header.Get("Role"); role != "admin" {
		w.Write([]byte("Not Authorized"))
		return
	}

	connection := GetDatabase()
	defer CloseDatabase(connection)

	var role Job
	role.Name = r.FormValue("name")
	role.Permission = r.FormValue("permission")

	var roleCheck Job
	connection.Where("name = ?", role.Name).First(&roleCheck)
	if roleCheck.Name != "" {
		fmt.Println("Role is already created")
		w.Write([]byte("Role is already created"))

		return
	}

	connection.NewRecord(role)
	connection.Create(&role)
	fmt.Println(connection.NewRecord(role))
	W.Write([]byte("Create Role successfully"))
	return
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	var job Job
	role := r.Header.Get("Role")
	connection.Where("name = ?", role).First(&job)
	if !strings.Contains(job.Permission, "c") && role != "admin" {
		w.Write([]byte("Not Authorized"))
		return
	}

	var user User
	user.Name = r.FormValue("name")
	user.Email = r.FormValue("email")
	user.Password = r.FormValue("password")
	user.Role = "user"

	var userTmp User
	connection.Where("email = ?", user.Email).First(&userTmp)

	if userTmp.Email != "" {
		fmt.Println("User is already exist")
		w.Write([]byte("User is already exist"))

		return
	}

	password, err := GeneratehashPassword(user.Password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	user.Password = password
	connection.NewRecord(user)
	connection.Create(&user)
	w.Write([]byte("Create user successfully"))

	return
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	var job Job
	role := r.Header.Get("Role")
	connection.Where("name = ?", role).First(&job)
	if !strings.Contains(job.Permission, "d") && role != "admin" {
		w.Write([]byte("Not Authorized"))
		return
	}

	email := r.URL.Path[len("/delete-user/"):]
	if email == "" {
		fmt.Println("Fill in user")
		w.Write([]byte("Fill in user"))

		return
	}
	var user User
	connection.Where("email = ?", email).First(&user)

	if user.Email == "" {
		fmt.Println("User is not exist")
		w.Write([]byte("User is not exist"))

		return
	}
	connection.Delete(&user)
	w.Write([]byte("Delete user successfully"))

	return
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	var job Job
	role := r.Header.Get("Role")
	connection.Where("name = ?", role).First(&job)
	if !strings.Contains(job.Permission, "u") && role != "admin" {
		w.Write([]byte("Not Authorized"))
		return
	}

	email := r.URL.Path[len("/update-user/"):]
	if email == "" {
		fmt.Println("Fill in user")
		w.Write([]byte("Fill in user"))
		return
	}

	var user User
	connection.Where("email = ?", email).First(&user)

	if user.Email == "" {
		fmt.Println("User is not exist")
		w.Write([]byte("User is not exist"))
		return
	}

	user.Password = r.FormValue("password")
	user.Name = r.FormValue("name")
	connection.Save(&user)
}

func ChangeRole(w http.ResponseWriter, r *http.Request) {
	if role := r.Header.Get("Role"); role != "admin" {
		w.Write([]byte("Not Authorized"))
		return
	}
	connection := GetDatabase()
	defer CloseDatabase(connection)

	role := r.FormValue("role")
	email := r.FormValue("email")

	var user User
	connection.Where("email = ?", email).First(&user)

	if user.Email == "" {
		fmt.Println("Not user available")
		w.Write([]byte("Not user available"))

		return
	}

	var job Job
	connection.Where("name = ?", role).First(&job)
	if job.Name == "" {
		fmt.Println("Not role available")
		w.Write([]byte("Not role available"))

		return
	}

	user.Role = role
	connection.Save(&user)
	fmt.Println("Change role successfully")
	w.Write([]byte("Change role successfully"))
	return
}

func LogOut(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("Token")
	cookie.Value = ""
	cookie.Expires = time.Unix(0, 0)
	http.SetCookie(w, cookie)
	w.Write([]byte("Log Out"))
}

func main() {
	InitMigration()
	InitRoute()
	ServerStart()
}