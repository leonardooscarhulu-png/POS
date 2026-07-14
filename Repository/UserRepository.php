<?php
declare(strict_types=1);

class UserRepository {
    private PDO $db;

    public function __construct(PDO $db) {
        $this->db = $db;
    }

    /** =========================
     *  LOGIN
     *  ========================= */
    public function verifyLogin(string $username, string $password): ?array {
        $stmt = $this->db->prepare(
            "SELECT id_user, username, pwd, role 
             FROM tbl_users 
             WHERE username = ? 
             LIMIT 1"
        );
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['pwd'])) {
            unset($user['pwd']); // keamanan
            return $user;
        }

        return null;
    }

    /** =========================
     *  AMBIL SEMUA USER
     *  ========================= */
    public function getAll(): array {
        $stmt = $this->db->query(
            "SELECT id_user, username, role, created_at
             FROM tbl_users
             ORDER BY id_user DESC"
        );
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /** ALIAS (biar users.php gak error) */
    public function findAll(): array {
        return $this->getAll();
    }

    /** =========================
     *  TAMBAH USER
     *  ========================= */
    public function insert(string $username, string $password, string $role): void {
        $hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $this->db->prepare(
            "INSERT INTO tbl_users (username, pwd, role)
             VALUES (?, ?, ?)"
        );
        $stmt->execute([$username, $hash, $role]);
    }

    /** =========================
     *  HAPUS USER
     *  ========================= */
    public function deleteById(int $id): void {
        $stmt = $this->db->prepare(
            "DELETE FROM tbl_users WHERE id_user = ?"
        );
        $stmt->execute([$id]);
    }
}
