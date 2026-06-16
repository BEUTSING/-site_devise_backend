<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20260613141742 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Create exchange rates and link offers to an admin-defined rate.';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE taux_change (id INT AUTO_INCREMENT NOT NULL, monnaie VARCHAR(10) NOT NULL, taux NUMERIC(10, 2) NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME DEFAULT NULL, UNIQUE INDEX UNIQ_TAUX_CHANGE_MONNAIE (monnaie), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('ALTER TABLE offres ADD taux_change_id INT DEFAULT NULL');
        $this->addSql('ALTER TABLE offres ADD CONSTRAINT FK_C6AC35445571E6A FOREIGN KEY (taux_change_id) REFERENCES taux_change (id) ON DELETE SET NULL');
        $this->addSql('CREATE INDEX IDX_C6AC35445571E6A ON offres (taux_change_id)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('ALTER TABLE offres DROP FOREIGN KEY FK_C6AC35445571E6A');
        $this->addSql('DROP INDEX IDX_C6AC35445571E6A ON offres');
        $this->addSql('ALTER TABLE offres DROP taux_change_id');
        $this->addSql('DROP TABLE taux_change');
    }
}
