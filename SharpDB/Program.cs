using System;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace SharpDB
{
    class Program
    {
        private static void ShowDatabaseAllRows(SqliteCommand dbc)
        {
            dbc.CommandText = "SELECT * FROM test";
            using (var reader = dbc.ExecuteReader())
            {
                if (reader.HasRows == false)
                {
                    Console.WriteLine("Database is empty");
                    return;
                }

                while (reader.Read())
                    Console.WriteLine($"ROW: ID [{reader.GetInt32(0)}] | LOGIN [{reader.GetString(1)}] | PASSWORD [{reader.GetString(2)}]");
            }
        }

        // Что вводить в логин:
        // 1. Чтобы пройти авторизацию как любой пользователь, к примеру ananas
        // ananas' LIMIT 1 -- '
        // 2. Чтобы удалить таблицу:
        // '; DROP TABLE test; -- '
        // 3. Чтобы добавить в таблицу новую строчку:
        // ananas'; INSERT INTO test values (NULL, 'zaraza', 'admin'); -- '

        static void CreateAndOpenConnection(ref SqliteConnection db)
        {
            var dbc = db.CreateCommand();

            dbc.CommandText = @"create table if not exists test(
                    id integer primary key autoincrement,
                    login text,
                    password text)";
            dbc.ExecuteNonQuery();

            dbc.CommandText = "insert into test values (NULL, 'ananas', '12345')";
            dbc.ExecuteNonQuery();

            dbc.CommandText = "insert into test values (NULL, 'kokos', '77777')";
            dbc.ExecuteNonQuery();

            dbc.CommandText = "insert into test values (NULL, 'parnas', '99999')";
            dbc.ExecuteNonQuery();
        }

        static void Main(string[] args)
        {
            var db = new SqliteConnection("Data Source=db.sqlite");
            db.Open();
            var dbc = db.CreateCommand();

            dbc.CommandText = @"create table if not exists test(
                    id integer primary key autoincrement,
                    login text,
                    password text)";
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

            dbc.CommandText = "insert into test values (NULL, 'ananas', '12345')";
            dbc.ExecuteNonQuery();

            dbc.CommandText = "insert into test values (NULL, 'kokos', '77777')";
            dbc.ExecuteNonQuery();

            dbc.CommandText = "insert into test values (NULL, 'parnas', '99999')";
            dbc.ExecuteNonQuery();

            string login = string.Empty,
                password = string.Empty;

            while (true)
            {
                Console.WriteLine("1. Use method without defense from sql injection");
                Console.WriteLine("2. Use method with defense via Parameters.AddWithValue");
                Console.WriteLine("3. Use method with defense via RegEx");
                Console.WriteLine("4. Show database rows");
                Console.WriteLine("5. Change login/pass");
                Console.WriteLine("6. Exit");
                Console.Write("Your choice: ");
                var answer = Console.ReadLine();
                switch (answer)
                {
                    case "1":
                        try { SQLQueryToInject(dbc, ref login, ref password); } catch { CreateAndOpenConnection(ref db); }
                        break;
                    case "2":
                        try { SQLQueryDefendedWithParameters(dbc, ref login, ref password); } catch { CreateAndOpenConnection(ref db); }
                        break;
                    case "3":
                        try { SQLQueryDefendedWithRegEx(dbc, ref login, ref password); } catch { CreateAndOpenConnection(ref db); }
                        break;
                    case "4":
                        try { ShowDatabaseAllRows(dbc); } catch { CreateAndOpenConnection(ref db); }
                        break;
                    case "5":
                        FillLoginAndPass(ref login, ref password);
                        break;
                    case "6":
                        return;
                }
            }
        }
        static void SQLQueryToInject(SqliteCommand dbc, ref string login, ref string password)
        {
            if (login.Length == 0 || password.Length == 0)
                FillLoginAndPass(ref login, ref password);
            Console.WriteLine("...[Начинает работу уязвимый метод SQLQueryToInject]...");

            var query = $"SELECT * FROM test WHERE `login` = '{login}' AND `password` = '{password}'";
            dbc.CommandText = query;
            using (var reader = dbc.ExecuteReader())
            {
                if (reader.HasRows == false)
                    Console.WriteLine($"DB dont have rows with login [{login}] & pass [{password}]");
                while (reader.Read())
                {
                    Console.WriteLine($"[Entered pass: {password} | Entered login: {login}]Access granted to: {reader.GetString(1)} with real pass: {reader.GetString(2)}");
                }
            }
        }
        static void SQLQueryDefendedWithParameters(SqliteCommand dbc, ref string login,ref string password)
        {
            if (login.Length == 0 || password.Length == 0)
                FillLoginAndPass(ref login, ref password);
            Console.WriteLine("...[Начинает работу защищенный метод SQLQueryDefendedWithParameters]...");
            var query = "SELECT * FROM test WHERE login = $log AND password = $pass";
            dbc.CommandText = query;
            dbc.Parameters.Clear();
            dbc.Parameters.AddWithValue("$log", login).SqliteType = SqliteType.Text;
            dbc.Parameters.AddWithValue("$pass", password).SqliteType = SqliteType.Text;

            using (var reader = dbc.ExecuteReader())
            {
                if (reader.HasRows == false)
                    Console.WriteLine($"Db dont have rows with login [{login}] & pass [{password}]");
                while (reader.Read())
                {
                    Console.WriteLine($"[Entered pass: {password}] Access granted to: [{reader.GetString(1)}] with real pass: [{reader.GetString(2)}]");
                }
            }
        }
        // RegEx: https://docs.microsoft.com/ru-ru/dotnet/standard/base-types/regular-expressions
        static void SQLQueryDefendedWithRegEx(SqliteCommand dbc, ref string login, ref string password)
        {
            if (login.Length == 0 || password.Length == 0)
                FillLoginAndPass(ref login, ref password);
            Console.WriteLine("...[Начинает работу защищенный метод SQLQueryDefendedWithRegEx]...");
            var pattern = "[A-Z|a-z|0-9|\\s]*"; // Любое количество символов любого регистра, любых цифр и пробелов

            bool isLoginMatched = false, isPasswordMatched = false;

            var loginMatches = Regex.Matches(login, pattern);
            foreach (var match in loginMatches)
            {
                if (match.ToString().Equals(login))
                {
                    Console.WriteLine($"Login [{match.ToString()}] is valid");
                    isLoginMatched = true;
                    break;
                }
            }

            var passMatches = Regex.Matches(password, pattern);
            foreach (var match in passMatches)
            {
                if (match.ToString().Equals(password))
                {
                    Console.WriteLine($"Password [{match.ToString()}] is valid...");
                    isPasswordMatched = true;
                }
            }

            if ((isLoginMatched && isPasswordMatched) == false)
            {
                Console.WriteLine("Login or Password not valid - sql query didn't send");
                return;
            }

            var query = $"SELECT * FROM test WHERE `login` = '{login}' AND `password` = '{password}'";
            dbc.CommandText = query;
            using (var reader = dbc.ExecuteReader())
            {
                if (reader.HasRows == false)
                    Console.WriteLine($"Account with login [{login}] & pass [{password}] doesn't exist in db");
                while (reader.Read())
                {
                    Console.WriteLine($"Entered data [login: {login}| pass: {password}] Access granted to: [login: {reader.GetString(1)}| pass: {reader.GetString(2)}]");
                }
            }

        }
        static void FillLoginAndPass(ref string login, ref string password)
        {
            Console.Write("Enter account login: ");
            login = Console.ReadLine();
            Console.Write("Enter account password: ");
            password= Console.ReadLine();

        }
    }
}
