using System;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace SharpDB
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var db = new SqliteConnection("Data Source=db.sqlite"))
            {
                db.Open();
                var dbc = db.CreateCommand();

                dbc.CommandText = @" create table if not exists test(
                    id integer primary key autoincrement,
                    login text,
                    password text)";
                dbc.ExecuteNonQuery();

                dbc.CommandText = $"insert into test values (NULL, 'kos', '12345')";
                dbc.ExecuteNonQuery();
                // Пример ввода логина для получения доступ к аккаунту с любым паролем:
                // kos' LIMIT 1 -- '
                // Запрос будет выгралядеть так при любом пароле:
                // SELECT * FROM test WHERE `login` = 'kos' LIMIT 1 -- ' AND password 'любойпароль'
                // -- ' Комментари, так что часть запроса [AND password 'любойпароль'] не будет отправлена в SQL запрос
                // Для защиты будем использовать:
                // 1. Pегулярные выражения, дабы ограничить ввод
                // 2. Передачу логина/пароля/любого поля таблицы через .Parameters.AddWithValue()
                // 3. Попробуем экранировать спецсимволы в запросе

                Console.Write("Enter ur login: ");
                var login = Console.ReadLine();
                Console.Write("Enter ur password: ");
                var password = Console.ReadLine();
                // select user
                SQLQueryToInject(dbc, login, password);
                SQLQueryDefendedWithParameters(dbc, login, password);
                SQLQueryDefendedWithRegEx(dbc, login, password);
                SQLQueryDefendedWithSpecialSymbolsChange(dbc, login, password);
                Console.ReadKey();
            }
        }
        static void SQLQueryToInject(SqliteCommand dbc, string login, string password)
        {
            Console.WriteLine("...[Начинает работу уязвимый метод SQLQueryToInject]...");

            var query = $"SELECT * FROM test WHERE `login` = '{login}' AND `password` = '{password}'";
            dbc.CommandText = query;
            using (var reader = dbc.ExecuteReader())
            {
                if (reader.HasRows == false)
                    Console.WriteLine($"DB dont have rows with login [{login}] & pass [{password}]");
                while (reader.Read())
                {
                    Console.WriteLine("[Entered pass: " + password + "]Access granted to: " + reader.GetString(1) + " with real pass:" + reader.GetString(2));
                }
            }
        }
        static void SQLQueryDefendedWithParameters(SqliteCommand dbc, string login, string password)
        {
            Console.WriteLine("...[Начинает работу защищенный метод SQLQueryDefendedWithParameters]...");
            var query = "SELECT * FROM test WHERE `login` = $login AND `password` = $pass";
            dbc.CommandText = query;
            dbc.Parameters.AddWithValue("$login", login);
            dbc.Parameters.AddWithValue("$pass", password);

            using (var reader = dbc.ExecuteReader())
            {
                if(reader.HasRows == false)
                    Console.WriteLine($"Db dont have rows with login [{login}] & pass [{password}]");
                while(reader.Read())
                {
                    Console.WriteLine($"[Entered pass: {password}] Access granted to: [{reader.GetString(1)}] with real pass: [{reader.GetString(2)}]");
                }    
            }
        }

        // RegEx: https://docs.microsoft.com/ru-ru/dotnet/standard/base-types/regular-expressions
        static void SQLQueryDefendedWithRegEx(SqliteCommand dbc, string login, string password)
        {
            Console.WriteLine("...[Начинает работу защищенный метод SQLQueryDefendedWithRegEx]...");
            var pattern = "[A-Z|a-z|0-9|\\s]*"; // Любое количество символов любого регистра, любых цифр и пробелов

            bool isLoginMatched = false, isPasswordMatched = false;

            var loginMatches = Regex.Matches(login, pattern);
            foreach(var match in loginMatches)
            {
                if (match.ToString().Equals(login))
                {
                    Console.WriteLine($"Login [{match.ToString()}] is valid");
                    isLoginMatched = true;
                    break;
                }
            }

            var passMatches = Regex.Matches(password, pattern);
            foreach(var match in passMatches)
            {
                if(match.ToString().Equals(password))
                {
                    Console.WriteLine($"Password [{match.ToString()}] is valid...");
                    isPasswordMatched = true;
                }
            }

            if( (isLoginMatched && isPasswordMatched) == false)
            {
                Console.WriteLine("Login or Password not valid - sql query didn't send");
                return;
            }

            var query = $"SELECT * FROM test WHERE `login` = '{login}' AND `password` = '{password}'";
            dbc.CommandText = query;
            using (var reader = dbc.ExecuteReader())
            {
                if(reader.HasRows == false)
                    Console.WriteLine($"Account with login [{login}] & pass [{password}] doesn't exist in db");
                while(reader.Read())
                {
                    Console.WriteLine($"Entered data [login: {login}| pass: {password}] Access granted to: [login: {reader.GetString(1)}| pass: {reader.GetString(2)}]");
                }
            }

        }
        static void SQLQueryDefendedWithSpecialSymbolsChange(SqliteCommand dbc, string login, string password)
        {
            Console.WriteLine("...[Начинает работу защищенный метод SQLQueryDefendedWithSpecialSymbolsChange]...");
            var specialChars = new char[] 
            {
                '\''
            };
            var clearedLogin = string.Empty;
            foreach(var ch in login)
            {
                foreach(var specialChar in specialChars)
                {
                    if(ch.Equals(specialChar))
                    {
                        clearedLogin += '\\';
                        break;
                    }
                }
                clearedLogin += ch;
            }

            var clearedPass = string.Empty;
            foreach (var ch in password)
            {
                foreach (var specialChar in specialChars)
                {
                    if (ch.Equals(specialChar))
                    {
                        clearedPass += '\\';
                        break;
                    }
                }
                clearedPass += ch;
            }

            var query = $"SELECT * FROM test WHERE `login` = '{clearedLogin}' AND `password` = '{clearedPass}'";
            dbc.CommandText = query;
            using (var reader = dbc.ExecuteReader())
            {
                if(reader.HasRows == false)
                    Console.WriteLine($"DB dont have rows with login [{clearedLogin}] & pass [{clearedPass}]");
                while(reader.Read())
                {
                    Console.WriteLine($"Entered data [login: {clearedLogin} | pass: {clearedPass}] access granted to [login: {reader.GetString(1)}| pass: {reader.GetString(2)}]");
                }
            }
        }
    }
}
