import java.sql.*;

public class DatabaseManager {
    //Ensure this points to the exact location of your existing file
    private static final String DB_URL = "jdbc:sqlite:database.db";

    static {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            System.err.println("SQLite Driver not found!");
        }
    }

    public static UserInfo verifyWithDatabase(String username, String receivedHash) {
        String sql = "SELECT uuid, role FROM users WHERE username = ? AND passwordDigest = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            pstmt.setString(2, receivedHash);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new UserInfo(
                            rs.getString("uuid"),
                            rs.getString("role")
                    );
                }
            }
        } catch (SQLException e) {
            //  if the path is wrong or the table name is different
            System.err.println("Database error: " + e.getMessage());
        }
        return null;
    }
}