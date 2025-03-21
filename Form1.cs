using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Linq;

namespace ApiApp
{
    public partial class Form1 : Form
    {
        private HttpListener _httpListener;
        private List<Account> _userList;

        public Form1()
        {
            InitializeComponent();
            InitializeUsers();
        }

        private void InitializeUsers()
        {
            _userList = new List<Account>
            {
                new Account { Id = 1, Email = "admin@gmail.com", Name = "Admin", Password = "admin", Role = "Admin" },
                new Account { Id = 2, Email = "vtk241_zoo1@student.ztu.edu.ua", Name = "Alexander1", Password = "123456", Role = "User" },
                new Account { Id = 3, Email = "vtk241_zoo2@student.ztu.edu.ua", Name = "Alexander2", Password = "123456", Role = "User" },
                new Account { Id = 4, Email = "vtk241_zoo3@student.ztu.edu.ua", Name = "Alexander3", Password = "123456", Role = "User" }
            };
        }

        private async void buttonStart_Click(object sender, EventArgs e)
        {
            if (_httpListener == null)
            {
                _httpListener = new HttpListener();
                _httpListener.Prefixes.Add("http://localhost:5000/");
                _httpListener.Start();
                textBoxOutput.AppendText($"API запущено за адресою http://localhost:5000/{Environment.NewLine}");

                await Task.Run(() => HandleRequests());
            }
        }

        private async void HandleRequests()
        {
            while (_httpListener.IsListening)
            {
                var context = await _httpListener.GetContextAsync();
                var request = context.Request;
                var response = context.Response;
                string responseContent = "";

                if (request.Url.AbsolutePath == "/favicon.ico")
                {
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Close();
                    continue;
                }

                if (request.HttpMethod == "GET")
                {
                    var user = ExtractUserFromRequest(request);
                    if (user == null)
                    {
                        response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        responseContent = "Неавторизовано";
                    }
                    else
                    {
                        HandleGetRequest(request, response, user, ref responseContent);
                    }
                }
                else if (request.HttpMethod == "POST")
                {
                    HandlePostRequest(request, response, ref responseContent);
                }
                else if (request.HttpMethod == "DELETE")
                {
                    HandleDeleteRequest(request, response, ref responseContent);
                }
                else if (request.HttpMethod == "PATCH")
                {
                    HandlePatchRequest(request, response, ref responseContent);
                }

                byte[] buffer = Encoding.UTF8.GetBytes(responseContent);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
                response.Close();

                Invoke((MethodInvoker)delegate
                {
                    textBoxOutput.AppendText($"{request.HttpMethod} {request.Url} -> {responseContent}{Environment.NewLine}");
                });
            }
        }

        private ClaimsPrincipal ExtractUserFromRequest(HttpListenerRequest request)
        {
            if (!request.Headers.AllKeys.Contains("Authorization")) return null;

            var authHeader = request.Headers["Authorization"];
            if (!authHeader.StartsWith("Bearer ")) return null;

            var token = authHeader.Substring("Bearer ".Length).Trim();
            return ValidateJwtToken(token);
        }

        private ClaimsPrincipal ValidateJwtToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("СекретнийКлюч_Для_Авторизації_Адміністраторів_І_Користувачів");

            try
            {
                var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return principal;
            }
            catch
            {
                return null;
            }
        }

        private void HandleGetRequest(HttpListenerRequest request, HttpListenerResponse response, ClaimsPrincipal user, ref string responseContent)
        {
            if (request.Url.AbsolutePath == "/users")
            {
                if (!user.IsInRole("Admin"))
                {
                    response.StatusCode = (int)HttpStatusCode.Forbidden;
                    responseContent = "Заборонено: тільки адміністратори можуть переглядати список користувачів";
                }
                else
                {
                    responseContent = JsonSerializer.Serialize(_userList);
                }
            }
            else if (request.Url.AbsolutePath.StartsWith("/users/"))
            {
                int userId = ExtractUserIdFromUrl(request.Url.AbsolutePath);

                if (user.IsInRole("Admin") || user.Identity.Name == _userList.FirstOrDefault(u => u.Id == userId)?.Email)
                {
                    var selectedUser = _userList.FirstOrDefault(u => u.Id == userId);

                    if (selectedUser != null)
                    {
                        responseContent = JsonSerializer.Serialize(selectedUser);
                    }
                    else
                    {
                        response.StatusCode = (int)HttpStatusCode.NotFound;
                        responseContent = "Користувача не знайдено";
                    }
                }
                else
                {
                    response.StatusCode = (int)HttpStatusCode.Forbidden;
                    responseContent = "Заборонено: у вас немає доступу до цього профілю";
                }
            }
        }

        private void HandlePostRequest(HttpListenerRequest request, HttpListenerResponse response, ref string responseContent)
        {
            if (request.Url.AbsolutePath == "/users")
            {
                var requestBody = new System.IO.StreamReader(request.InputStream).ReadToEnd();
                var newUser = JsonSerializer.Deserialize<Account>(requestBody);

                if (newUser != null)
                {
                    newUser.Id = _userList.Count + 1;
                    _userList.Add(newUser);
                    responseContent = JsonSerializer.Serialize(newUser);
                }
            }
            else if (request.Url.AbsolutePath == "/login")
            {
                var requestBody = new System.IO.StreamReader(request.InputStream).ReadToEnd();
                var loginData = JsonSerializer.Deserialize<Account>(requestBody);

                var user = _userList.FirstOrDefault(u => u.Email == loginData.Email && u.Password == loginData.Password);

                if (user != null)
                {
                    var token = CreateJwtToken(user);
                    responseContent = JsonSerializer.Serialize(new { Token = token });
                }
                else
                {
                    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    responseContent = "Неправильний email або пароль";
                }
            }
        }

        private void HandleDeleteRequest(HttpListenerRequest request, HttpListenerResponse response, ref string responseContent)
        {
            var user = ExtractUserFromRequest(request);
            if (user == null)
            {
                response.StatusCode = (int)HttpStatusCode.Unauthorized;
                responseContent = "Неавторизовано";
            }
            else if (!user.IsInRole("Admin"))
            {
                response.StatusCode = (int)HttpStatusCode.Forbidden;
                responseContent = "Заборонено: тільки адміністратори можуть видаляти користувачів";
            }
            else
            {
                int userId = ExtractUserIdFromUrl(request.Url.AbsolutePath);
                _userList.RemoveAll(u => u.Id == userId);
                responseContent = "Користувача видалено";
            }
        }

        private void HandlePatchRequest(HttpListenerRequest request, HttpListenerResponse response, ref string responseContent)
        {
            var user = ExtractUserFromRequest(request);
            if (user == null)
            {
                response.StatusCode = (int)HttpStatusCode.Unauthorized;
                responseContent = "Неавторизовано";
            }
            else
            {
                int userId = ExtractUserIdFromUrl(request.Url.AbsolutePath);
                var existingUser = _userList.Find(u => u.Id == userId);

                if (existingUser == null)
                {
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    responseContent = "Користувача не знайдено";
                }
                else if (user.IsInRole("Admin") || user.Identity.Name == existingUser.Email)
                {
                    var requestBody = new System.IO.StreamReader(request.InputStream).ReadToEnd();
                    var updatedUser = JsonSerializer.Deserialize<Account>(requestBody);

                    if (updatedUser != null)
                    {
                        if (!string.IsNullOrEmpty(updatedUser.Name))
                        {
                            existingUser.Name = updatedUser.Name;
                        }
                        if (!string.IsNullOrEmpty(updatedUser.Email))
                        {
                            existingUser.Email = updatedUser.Email;
                        }
                        responseContent = JsonSerializer.Serialize(existingUser);
                    }
                    else
                    {
                        responseContent = "Неправильний формат даних";
                    }
                }
                else
                {
                    response.StatusCode = (int)HttpStatusCode.Forbidden;
                    responseContent = "Заборонено: ви можете змінювати тільки свій профіль";
                }
            }
        }

        private int ExtractUserIdFromUrl(string url)
        {
            var segments = url.Split('/');
            return int.TryParse(segments.Last(), out int userId) ? userId : -1;
        }

        private string CreateJwtToken(Account user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("СекретнийКлюч_Для_Авторизації_Адміністраторів_І_Користувачів");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    public class Account
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
}
